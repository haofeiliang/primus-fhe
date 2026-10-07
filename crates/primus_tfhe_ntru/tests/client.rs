use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_lwe::{LweCiphertext, LweParameters, LwePublicKey, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use primus_tfhe_ntru::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, ClientError, ClientKey, EncryptionKey,
    Encryptor, GadgetEncryptionConfig, Lwe, TfheKeyError, TfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn check<M: RingContext<u32>>(modulus: M, plain_modulus: u32) {
    let input_codec = RoundedCodec::new(plain_modulus, modulus);
    let ring = NtruParameters::new(
        PolyLength::new(32),
        plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        1.4,
    );
    let params = TfheParameters::try_new(
        LweEncryptionParameters::new(
            LweDimension::new(4),
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::try_with_basis(
            &ring,
            ApproxSignedBasis::new(
                ring.cipher_modulus_value(),
                DecompositionBaseLog::new(8),
                None,
            ),
        )
        .unwrap(),
        GadgetEncryptionConfig {
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: ring.noise_distribution().standard_deviation(),
        },
    )
    .unwrap();
    let mut accumulator = vec![0; ring.poly_length().get()];
    accumulator[0] = 1;
    let client = ClientKey::new(
        primus_lwe::LweSecretKey::new(vec![1, 0, 1, 1], SecretKeyDistr::UniformBinary, modulus),
        NtruSecretKey::new(accumulator, SecretKeyDistr::UniformBinary),
    );
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_504b);
    let public = params
        .try_generate_public_key(client.external_lwe_secret_key(), &mut rng)
        .unwrap();
    assert_eq!(public.dimension(), LweDimension::new(4)); // Independent external LWE dimension.
    // External LWE encryption uses its own noise sampler.
    let lwe = params.external_lwe();
    let encoded = input_codec.encode_value(1, primus_encoding::PlaintextEmbedding::Unsigned);
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut reference_rng = StdRng::seed_from_u64(seed);
    let expected = client.external_lwe_secret_key().as_view().encrypt_encoded(
        encoded,
        modulus,
        lwe.cipher_modulus_uniform_distr(),
        lwe.noise_distribution(),
        &mut reference_rng,
    );
    assert_eq!(
        params
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap()
            .encrypt(1, &mut rng)
            .unwrap(),
        expected
    );
    assert_eq!(rng.next_u64(), reference_rng.next_u64());
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut reference_rng = StdRng::seed_from_u64(seed);
    let expected = public.encrypt_encoded(
        encoded,
        modulus,
        lwe.noise_distribution(),
        &mut reference_rng,
    );
    assert_eq!(
        params
            .public_encryptor(&public, &input_codec)
            .unwrap()
            .encrypt(1, &mut rng)
            .unwrap(),
        expected
    );
    assert_eq!(rng.next_u64(), reference_rng.next_u64());
    check_reused_output(
        &params,
        &client,
        &input_codec,
        params.public_encryptor(&public, &input_codec).unwrap(),
    );
    check_reused_output(
        &params,
        &client,
        &input_codec,
        params
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap(),
    );
    check_boolean_client(&params, &client, &input_codec);

    // Binary coefficients fit both moduli; binding must use the owning metadata.
    let wrong_domain = ClientKey::new(
        LweSecretKey::new(
            vec![1, 0, 1, 1],
            SecretKeyDistr::UniformBinary,
            BarrettModulus::new(65_537u32),
        ),
        client.accumulator_ntru_secret_key().clone(),
    );
    let error = primus_tfhe_ntru::TfheClientError::IncompatibleKey(
        TfheKeyError::LweSecretKeyModulusMismatch,
    );
    assert_eq!(
        params
            .encryptor(wrong_domain.external_lwe_secret_key(), &input_codec)
            .err(),
        Some(error.clone())
    );
    assert_eq!(
        params
            .decryptor(wrong_domain.external_lwe_secret_key(), &input_codec)
            .err(),
        Some(error)
    );
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut untouched = StdRng::seed_from_u64(seed);
    assert_eq!(
        params
            .try_generate_public_key(wrong_domain.external_lwe_secret_key(), &mut rng)
            .err(),
        Some(TfheKeyError::LweSecretKeyModulusMismatch),
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());

    let foreign_params = LweParameters::new(
        LweDimension::new(4),
        4,
        BarrettModulus::new(65_537u32),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let foreign_secret = LweSecretKey::generate(foreign_params.encryption_parameters(), &mut rng);
    let foreign = LwePublicKey::generate(
        foreign_secret.as_view(),
        foreign_params.encryption_parameters(),
        &mut rng,
    );
    assert_eq!(
        params.public_encryptor(&foreign, &input_codec).err(),
        Some(ClientError::PublicKeyModulusMismatch)
    );
    let full_params = LweParameters::new(
        LweDimension::new(8),
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let full_secret = LweSecretKey::generate(full_params.encryption_parameters(), &mut rng);
    let full = LwePublicKey::generate(
        full_secret.as_view(),
        full_params.encryption_parameters(),
        &mut rng,
    );
    assert_eq!(
        params.public_encryptor(&full, &input_codec).err(),
        Some(ClientError::KeyDimensionMismatch {
            expected: 4,
            actual: 8
        })
    );
    let bad_client = ClientKey::new(
        primus_lwe::LweSecretKey::new(
            (vec![1, -1, 1, 1, 0, 0, 0, 0])[..4]
                .iter()
                .map(|&s| primus_integer::SignedInteger::cast_to_unsigned(s))
                .collect(),
            SecretKeyDistr::UniformBinary,
            modulus,
        ),
        NtruSecretKey::new(
            vec![1, 0, 0, 0, 0, 0, 0, 0]
                .into_iter()
                .chain(std::iter::repeat(0))
                .take(32)
                .collect(),
            SecretKeyDistr::UniformBinary,
        ),
    );
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected_rng = StdRng::seed_from_u64(seed);
    assert_eq!(
        params
            .try_generate_public_key(bad_client.external_lwe_secret_key(), &mut rng)
            .err(),
        Some(TfheKeyError::InvalidClientSecretKeyCoefficient)
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
}

fn check_boolean_client<M: RingContext<u32>>(
    parameters: &TfheParameters<u32, M>,
    client: &ClientKey<u32>,
    input_codec: &RoundedCodec<u32, M>,
) {
    if input_codec.plaintext_modulus() != 4 {
        assert_eq!(
            BooleanEncryptor::try_new(
                parameters
                    .encryptor(client.external_lwe_secret_key(), input_codec)
                    .unwrap()
            )
            .err(),
            Some(BooleanError::PlaintextModulusMustBeFour)
        );
        assert_eq!(
            BooleanDecryptor::try_new(
                parameters
                    .decryptor(client.external_lwe_secret_key(), input_codec)
                    .unwrap()
            )
            .err(),
            Some(BooleanError::PlaintextModulusMustBeFour)
        );
        return;
    }
    let encryptor = BooleanEncryptor::try_new(
        parameters
            .encryptor(client.external_lwe_secret_key(), input_codec)
            .unwrap(),
    )
    .unwrap();
    let decryptor = BooleanDecryptor::try_new(
        parameters
            .decryptor(client.external_lwe_secret_key(), input_codec)
            .unwrap(),
    )
    .unwrap();
    let raw_encryptor = parameters
        .encryptor(client.external_lwe_secret_key(), input_codec)
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0xB202);
    // Reuse a stack-backed view; only its mask/body may be overwritten.
    // The fixture's external LWE dimension is four, independent of ring N.
    let mut storage = [u32::MAX; 7];
    let mut output = Lwe::new(&mut storage[1..6]);
    for message in [false, true, false] {
        encryptor
            .encrypt_to(message, output.as_mut_view(), &mut rng)
            .unwrap();
        let result = decryptor.decrypt(output.as_view());
        assert_eq!(result, Ok(message));
    }
    assert_eq!([storage[0], storage[6]], [u32::MAX; 2]);

    for message in [2, 3] {
        let invalid = raw_encryptor.encrypt(message, &mut rng).unwrap();
        assert_eq!(
            decryptor.decrypt(invalid.as_view()),
            Err(BooleanError::InvalidPlaintext)
        );
    }
    let dimension = parameters.external_lwe_dimension().get();
    let mut wrong = LweCiphertext::new(vec![1; dimension]);
    let before = wrong.clone();
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected_rng = StdRng::seed_from_u64(seed);
    let error = BooleanError::Client(ClientError::CiphertextDimensionMismatch {
        expected: dimension,
        actual: dimension - 1,
    });
    assert_eq!(
        encryptor.encrypt_to(true, wrong.as_mut_view(), &mut rng),
        Err(error.clone())
    );
    assert_eq!(wrong, before);
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert_eq!(decryptor.decrypt(wrong.as_view()), Err(error));
}

#[test]
fn clients_preserve_encodings_and_reject_incompatible_inputs() {
    for plain_modulus in [4, 5] {
        check(NativeModulus::new(), plain_modulus);
        check(BarrettModulus::new(132_120_577), plain_modulus);
    }
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
    input_codec: &RoundedCodec<u32, M>,
    encryptor: Encryptor<'_, u32, M, Key>,
) where
    M: RingContext<u32>,
    Key: EncryptionKey<u32, M>,
{
    let decryptor = parameters
        .decryptor(client.external_lwe_secret_key(), input_codec)
        .unwrap();
    let dimension = parameters.external_lwe_dimension().get();
    let t = input_codec.plaintext_modulus();
    let mut rng = StdRng::seed_from_u64(0x434c_4945_4e54);
    let mut expected_rng = StdRng::seed_from_u64(0x434c_4945_4e54);
    let mut output = LweCiphertext::new(vec![u32::MAX; dimension + 1]);
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
        let encrypt_to = |message, output: &mut LweCiphertext<u32>, rng: &mut StdRng| match encoding
        {
            Encoding::Unsigned => encryptor.encrypt_to(message, output.as_mut_view(), rng),
            Encoding::Padded => encryptor.encrypt_padded_to(message, output.as_mut_view(), rng),
            Encoding::Centered => encryptor.encrypt_centered_to(message, output.as_mut_view(), rng),
        };
        // Compare identical randomness across the small domain, including the
        // centered sign boundary, then overwrite the last ciphertext with zero.
        for message in (0..limit).chain([0]) {
            let expected = encrypt(message, &mut expected_rng).unwrap();
            let result = encrypt_to(message, &mut output, &mut rng);
            result.unwrap();
            assert_eq!(output, expected);
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
            assert_eq!(encrypt_to(message, &mut output, &mut rng), Err(error));
            assert_eq!(output, before);
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
        for actual in [0, dimension - 1, dimension + 1] {
            let mut wrong = LweCiphertext::new(vec![u32::MAX; actual + 1]);
            let before = wrong.clone();
            assert_eq!(
                encrypt_to(0, &mut wrong, &mut rng),
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
