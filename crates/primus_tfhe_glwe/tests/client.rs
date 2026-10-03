use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_glwe::{GlweParameters, GlweSecretKey, GlweSize, SecretKeyDistr};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::{LweCiphertext, LweParameters, LwePublicKey, LweSecretKey, LweSecretKeyRef};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_test_allocations as allocations;
use primus_tfhe_glwe::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, ClientError, ClientKey, EncryptionKey,
    Encryptor, Lwe, PbsOrder, TfheClientError, TfheKeyError, TfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn check<M: RingContext<u32>>(modulus: M, plain_modulus: u32) {
    let codec = RoundedCodec::new(plain_modulus, modulus);
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        // Two different external dimensions and a signed ring secret including -1.
        let small = LweParameters::new(
            LweDimension::new(4),
            plain_modulus,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let glwe = GlweParameters::new(
            GlweDimension::new(2),
            32,
            plain_modulus,
            modulus,
            SecretKeyDistr::UniformTernary,
            1.4,
        );
        let bsk = ApproxSignedBasis::new(
            glwe.cipher_modulus_value(),
            DecompositionBaseLog::new(8),
            None,
        );
        let params = TfheParameters::try_new(
            small.into_inner(),
            primus_glwe::GgswParameters::try_with_basis(&glwe, bsk).unwrap(),
            ApproxSignedBasis::new(modulus.explicit_value(), DecompositionBaseLog::new(8), None),
            order,
        )
        .unwrap();
        let client = ClientKey::new(
            LweSecretKey::new(vec![1, 0, 1, 1], SecretKeyDistr::UniformBinary, modulus),
            GlweSecretKey::new(
                vec![1, -1, 0, 1, 0, -1, 0, 1, 1, 0, -1, 0, 1, 0, 0, -1].repeat(4),
                GlweSize::new(GlweDimension::new(2), PolyLength::new(32)),
                SecretKeyDistr::UniformTernary,
            ),
            order,
        );
        let mut rng = StdRng::seed_from_u64(0x474c_5745_504b);
        let public = client.try_generate_public_key(&params, &mut rng).unwrap();
        assert_eq!(
            public.dimension(),
            LweDimension::new(if order == PbsOrder::BootstrapKeyswitch {
                4
            } else {
                64
            })
        );
        // Independent raw-LWE calls pin the key and noise selected by each PBS order.
        let (secret, uniform, noise) = match order {
            PbsOrder::BootstrapKeyswitch => (
                client.small_lwe_secret_key().as_view(),
                params.small_lwe().cipher_modulus_uniform_distr(),
                params.small_lwe().noise_distribution(),
            ),
            PbsOrder::KeyswitchBootstrap => (
                LweSecretKeyRef::Signed(client.glwe_secret_key().as_slice()),
                params
                    .blind_rotation_ggsw()
                    .inner()
                    .cipher_modulus_uniform_distr(),
                params.blind_rotation_ggsw().noise_distribution(),
            ),
        };
        let encoded = codec.encode_value(1, primus_encoding::PlaintextEmbedding::Unsigned);
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut reference_rng = StdRng::seed_from_u64(seed);
        let expected = secret.encrypt_encoded(encoded, modulus, uniform, noise, &mut reference_rng);
        assert_eq!(
            params
                .encryptor(&client, &codec)
                .unwrap()
                .encrypt(1, &mut rng)
                .unwrap(),
            expected
        );
        assert_eq!(rng.next_u64(), reference_rng.next_u64());
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut reference_rng = StdRng::seed_from_u64(seed);
        let expected = public.encrypt_encoded(encoded, modulus, noise, &mut reference_rng);
        assert_eq!(
            params
                .public_encryptor(&public, &codec)
                .unwrap()
                .encrypt(1, &mut rng)
                .unwrap(),
            expected
        );
        assert_eq!(rng.next_u64(), reference_rng.next_u64());
        check_reused_output(
            &params,
            &client,
            &codec,
            params.public_encryptor(&public, &codec).unwrap(),
        );
        check_reused_output(
            &params,
            &client,
            &codec,
            params.encryptor(&client, &codec).unwrap(),
        );

        // Binary coefficients fit both moduli; binding must use the owning metadata.
        let wrong_domain = ClientKey::new(
            LweSecretKey::new(
                vec![1, 0, 1, 1],
                SecretKeyDistr::UniformBinary,
                BarrettModulus::new(65_537u32),
            ),
            client.glwe_secret_key().clone(),
            order,
        );
        let error = primus_tfhe_glwe::TfheClientError::IncompatibleKey(
            TfheKeyError::LweSecretKeyModulusMismatch,
        );
        assert_eq!(
            params.encryptor(&wrong_domain, &codec).err(),
            Some(error.clone())
        );
        assert_eq!(params.decryptor(&wrong_domain, &codec).err(), Some(error));
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut untouched = StdRng::seed_from_u64(seed);
        assert_eq!(
            wrong_domain
                .try_generate_public_key(&params, &mut rng)
                .err(),
            Some(TfheKeyError::LweSecretKeyModulusMismatch),
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());

        // Public-key binding also rejects a foreign modulus with the same dimension.
        let foreign_params = LweParameters::new(
            public.dimension(),
            4,
            BarrettModulus::new(65_537u32),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let foreign_secret = LweSecretKey::generate(foreign_params.inner(), &mut rng);
        let foreign =
            LwePublicKey::generate(foreign_secret.as_view(), foreign_params.inner(), &mut rng);
        assert_eq!(
            params.public_encryptor(&foreign, &codec).err(),
            Some(ClientError::PublicKeyModulusMismatch)
        );
        let short_params = LweParameters::new(
            LweDimension::new(3),
            4,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let short_secret = LweSecretKey::generate(short_params.inner(), &mut rng);
        let short = LwePublicKey::generate(short_secret.as_view(), short_params.inner(), &mut rng);
        assert_eq!(
            params.public_encryptor(&short, &codec).err(),
            Some(ClientError::KeyDimensionMismatch {
                expected: public.dimension().get(),
                actual: 3,
            })
        );
        let wrong_order = if order == PbsOrder::BootstrapKeyswitch {
            PbsOrder::KeyswitchBootstrap
        } else {
            PbsOrder::BootstrapKeyswitch
        };
        let (small_key, ring_key, _) = client.into_parts();
        let wrong_client = ClientKey::new(small_key, ring_key, wrong_order);
        let error = TfheClientError::IncompatibleKey(TfheKeyError::PbsOrderMismatch {
            expected: order,
            actual: wrong_order,
        });
        assert_eq!(
            params.encryptor(&wrong_client, &codec).err(),
            Some(error.clone())
        );
        assert_eq!(params.decryptor(&wrong_client, &codec).err(), Some(error));
        let seed = rng.next_u64();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut expected_rng = StdRng::seed_from_u64(seed);
        assert_eq!(
            wrong_client
                .try_generate_public_key(&params, &mut rng)
                .err(),
            Some(TfheKeyError::PbsOrderMismatch {
                expected: order,
                actual: wrong_order,
            })
        );
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}

#[test]
fn both_external_domains_support_public_clients_and_reject_incompatible_keys() {
    for plain_modulus in [4, 5] {
        check(NativeModulus::new(), plain_modulus);
        check(BarrettModulus::new(132_120_577), plain_modulus);
    }
}

#[test]
fn boolean_clients_reject_other_plaintext_moduli() {
    let mut rng = StdRng::seed_from_u64(0x424f_4f4c);
    let modulus = NativeModulus::<u32>::new();
    for t in [3, 5] {
        let codec = RoundedCodec::new(t, modulus);
        let parameters = TfheParameters::try_new(
            (LweParameters::new(
                LweDimension::new(4),
                t,
                modulus,
                SecretKeyDistr::UniformBinary,
                0.7,
            ))
            .into_inner(),
            primus_glwe::GgswParameters::try_with_basis(
                &(GlweParameters::new(
                    GlweDimension::new(1),
                    32,
                    t,
                    modulus,
                    SecretKeyDistr::UniformTernary,
                    0.7,
                )),
                ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None),
            )
            .unwrap(),
            ApproxSignedBasis::new(None, DecompositionBaseLog::new(8), None),
            PbsOrder::BootstrapKeyswitch,
        )
        .unwrap();
        let client = ClientKey::generate(&parameters, &mut rng);
        client.check_compatible(&parameters).unwrap();
        assert_eq!(
            BooleanEncryptor::try_new(parameters.encryptor(&client, &codec).unwrap()).err(),
            Some(BooleanError::PlaintextModulusMustBeFour),
        );
        assert_eq!(
            BooleanDecryptor::try_new(parameters.decryptor(&client, &codec).unwrap()).err(),
            Some(BooleanError::PlaintextModulusMustBeFour),
        );
    }
}

#[test]
fn binding_checks_small_secret_coefficients_without_restricting_gaussian_accumulator() {
    fn check<M: RingContext<u32>>(modulus: M) {
        let codec = RoundedCodec::new(4, modulus);
        let gaussian = SecretKeyDistr::gaussian(1.0);
        for distr in [
            SecretKeyDistr::UniformBinary,
            SecretKeyDistr::UniformTernary,
        ] {
            let parameters = TfheParameters::try_new(
                (LweParameters::new(LweDimension::new(4), 4, modulus, distr, 0.7)).into_inner(),
                primus_glwe::GgswParameters::try_with_basis(
                    &(GlweParameters::new(GlweDimension::new(1), 32, 4, modulus, gaussian, 0.7)),
                    ApproxSignedBasis::new(
                        modulus.explicit_value(),
                        DecompositionBaseLog::new(8),
                        None,
                    ),
                )
                .unwrap(),
                ApproxSignedBasis::new(
                    modulus.explicit_value(),
                    DecompositionBaseLog::new(8),
                    None,
                ),
                PbsOrder::BootstrapKeyswitch,
            )
            .unwrap();
            let minus_one = modulus.minus_one();
            for coefficient in [0, 1, minus_one, 2, minus_one - 1] {
                let client = ClientKey::new(
                    LweSecretKey::new(vec![0, 1, 0, coefficient], distr, modulus),
                    GlweSecretKey::new(
                        vec![2; 32],
                        GlweSize::new(GlweDimension::new(1), PolyLength::new(32)),
                        gaussian,
                    ),
                    PbsOrder::BootstrapKeyswitch,
                );
                let expected =
                    if coefficient <= 1 || (distr.is_ternary() && coefficient == minus_one) {
                        None
                    } else {
                        Some(TfheClientError::IncompatibleKey(
                            TfheKeyError::InvalidLweSecretKeyCoefficient,
                        ))
                    };
                assert_eq!(parameters.encryptor(&client, &codec).err(), expected);
            }
        }
    }
    check(NativeModulus::new());
    check(BarrettModulus::new(132_120_577));
}

#[derive(Clone, Copy)]
enum Encoding {
    Unsigned,
    Padded,
    Centered,
}

fn check_reused_output<M, Key>(
    parameters: &TfheParameters<u32, M>,
    client: &ClientKey<u32>,
    codec: &RoundedCodec<u32, M>,
    encryptor: Encryptor<'_, u32, M, Key>,
) where
    M: RingContext<u32>,
    Key: EncryptionKey<u32, M>,
{
    let decryptor = parameters.decryptor(client, codec).unwrap();
    let dimension = parameters.external_lwe_dimension().get();
    let t = codec.plaintext_modulus();
    let mut rng = StdRng::seed_from_u64(0x434c_4945_4e54);
    let mut expected_rng = StdRng::seed_from_u64(0x434c_4945_4e54);
    // Borrow non-Vec storage through the same client path for both PBS orders.
    let mut output = Lwe::new(vec![u32::MAX; dimension + 1].into_boxed_slice());
    for (encoding, limit) in [
        (Encoding::Unsigned, t),
        (Encoding::Padded, t.div_ceil(2)),
        (Encoding::Centered, t),
    ] {
        let encrypt = |message, rng: &mut StdRng| match encoding {
            Encoding::Unsigned => encryptor.encrypt(message, rng),
            Encoding::Padded => encryptor.encrypt_padded(message, rng),
            Encoding::Centered => encryptor.encrypt_centered(message, rng),
        };
        let encrypt_to = |message, output: Lwe<&mut [u32]>, rng: &mut StdRng| match encoding {
            Encoding::Unsigned => encryptor.encrypt_to(message, output, rng),
            Encoding::Padded => encryptor.encrypt_padded_to(message, output, rng),
            Encoding::Centered => encryptor.encrypt_centered_to(message, output, rng),
        };
        // Compare identical randomness across the small domain, including the
        // centered sign boundary, then overwrite the last ciphertext with zero.
        for message in (0..limit).chain([0]) {
            let (expected, allocation) =
                allocations::measure(|| encrypt(message, &mut expected_rng).unwrap());
            assert_eq!(
                allocation.count, 1,
                "only the ciphertext should be allocated"
            );
            assert_eq!(
                allocation.allocated_bytes,
                (dimension + 1) * size_of::<u32>()
            );
            let (result, allocation) =
                allocations::measure(|| encrypt_to(message, output.as_mut_view(), &mut rng));
            result.unwrap();
            assert_eq!(allocation.count, 0, "client encryption must not allocate");
            assert_eq!(output.as_ref(), expected.as_ref());
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
            assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), message);
        }
        let padded_error = matches!(encoding, Encoding::Padded)
            .then_some((limit, ClientError::MessageOutsidePaddedDomain));
        for (message, error) in [(t, ClientError::MessageOutOfRange)]
            .into_iter()
            .chain(padded_error)
        {
            let before = output.clone();
            assert_eq!(encrypt(message, &mut rng).err(), Some(error.clone()));
            assert_eq!(
                encrypt_to(message, output.as_mut_view(), &mut rng),
                Err(error)
            );
            assert_eq!(output, before);
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
        for actual in [0, dimension - 1, dimension + 1] {
            let mut wrong = LweCiphertext::new(vec![u32::MAX; actual + 1]);
            let before = wrong.clone();
            assert_eq!(
                encrypt_to(0, wrong.as_mut_view(), &mut rng),
                Err(ClientError::CiphertextDimensionMismatch {
                    expected: dimension,
                    actual
                })
            );
            assert_eq!(wrong, before);
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }
}

#[test]
fn message_codec_must_match_the_key_ciphertext_modulus() {
    use primus_lwe::LweParametersInner;
    use primus_tfhe_glwe::{DecompositionConfig, LookupTableError, TfheConfig};
    let parameters = TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParametersInner::new(
            LweDimension::new(4),
            BarrettModulus::new(132_120_577u32),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: 32,
        accumulator_secret_key_distr: SecretKeyDistr::UniformTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        pbs_order: PbsOrder::BootstrapKeyswitch,
    })
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x434f_4445_4351);
    let client = ClientKey::generate(&parameters, &mut rng);
    let public = client
        .try_generate_public_key(&parameters, &mut rng)
        .unwrap();
    let codec = RoundedCodec::new(4, BarrettModulus::new(65_537u32));
    // Reject the codec during binding, before any encryption or LUT callback.
    let error = TfheClientError::from(ClientError::CodecModulusMismatch);
    assert_eq!(
        parameters.encryptor(&client, &codec).err(),
        Some(error.clone())
    );
    assert_eq!(parameters.decryptor(&client, &codec).err(), Some(error));
    assert_eq!(
        parameters.public_encryptor(&public, &codec).err(),
        Some(ClientError::CodecModulusMismatch)
    );
    assert_eq!(
        parameters.lookup_table_compiler(&codec).err(),
        Some(LookupTableError::InputModulusMismatch)
    );
}
