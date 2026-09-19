use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweParameters, GlweSecretKey, GlweSize, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters, LwePublicKey, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use primus_test_allocations as allocations;
use primus_tfhe_glwe::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, ClientKey, Decryptor, EncryptionKey,
    Encryptor, PbsOrder, TfheClientError, TfheKeyError, TfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn check<M: RingContext<u32>>(modulus: M, plain_modulus: u32) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        // Two different external dimensions and a signed ring secret including -1.
        let small = LweParameters::new(
            4,
            plain_modulus,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let glwe = GlweParameters::new(
            2,
            8,
            plain_modulus,
            modulus,
            SecretKeyDistr::UniformTernary,
            1.4,
        );
        let bsk = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 8, None);
        let params = TfheParameters::try_new(
            small,
            glwe,
            bsk,
            ApproxSignedBasis::new(modulus.explicit_value(), 8, None),
            order,
        )
        .unwrap();
        let client = ClientKey::new(
            LweSecretKey::new(vec![1, 0, 1, 1], SecretKeyDistr::UniformBinary),
            GlweSecretKey::new(
                vec![1, -1, 0, 1, 0, -1, 0, 1, 1, 0, -1, 0, 1, 0, 0, -1],
                GlweSize::new(2, 8),
                SecretKeyDistr::UniformTernary,
            ),
            order,
        );
        let mut rng = StdRng::seed_from_u64(0x474c_5745_504b);
        let public = client.try_generate_public_key(&params, &mut rng).unwrap();
        assert_eq!(
            public.dimension(),
            if order == PbsOrder::BootstrapKeyswitch {
                4
            } else {
                16
            }
        );
        check_reused_output(&params, &client, &public);
        check_reused_output(&params, &client, &client);

        // Public-key binding must reject same-word-size foreign moduli, not just dimensions.
        let foreign_params = LweParameters::new(
            public.dimension(),
            4,
            BarrettModulus::new(65_537u32),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let foreign_secret = LweSecretKey::generate(&foreign_params, &mut rng);
        let foreign = LwePublicKey::generate(foreign_secret.as_view(), &foreign_params, &mut rng);
        assert_eq!(
            Encryptor::try_new(&params, &foreign).err(),
            Some(TfheClientError::PublicKeyModulusMismatch)
        );
        let short_params = LweParameters::new(3, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let short_secret = LweSecretKey::generate(&short_params, &mut rng);
        let short = LwePublicKey::generate(short_secret.as_view(), &short_params, &mut rng);
        assert_eq!(
            Encryptor::try_new(&params, &short).err(),
            Some(TfheClientError::PublicKeyDimensionMismatch {
                expected: public.dimension(),
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
        let parameters = TfheParameters::try_new(
            LweParameters::new(4, t, modulus, SecretKeyDistr::UniformBinary, 0.7),
            GlweParameters::new(1, 8, t, modulus, SecretKeyDistr::UniformTernary, 0.7),
            ApproxSignedBasis::new(None, 8, None),
            ApproxSignedBasis::new(None, 8, None),
            PbsOrder::BootstrapKeyswitch,
        )
        .unwrap();
        let client = ClientKey::generate(&parameters, &mut rng);
        client.check_compatible(&parameters).unwrap();
        assert_eq!(
            BooleanEncryptor::try_new(&parameters, &client).err(),
            Some(BooleanError::PlaintextModulusMustBeFour),
        );
        assert_eq!(
            BooleanDecryptor::try_new(&parameters, &client).err(),
            Some(BooleanError::PlaintextModulusMustBeFour),
        );
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
    key: &Key,
) where
    M: RingContext<u32>,
    Key: EncryptionKey<u32, M>,
{
    let encryptor = Encryptor::try_new(parameters, key).unwrap();
    let decryptor = Decryptor::try_new(parameters, client).unwrap();
    let dimension = parameters.external_lwe_dimension();
    let t = parameters.plain_modulus_value();
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
            Encoding::Unsigned => encryptor.encrypt_to(message, output, rng),
            Encoding::Padded => encryptor.encrypt_padded_to(message, output, rng),
            Encoding::Centered => encryptor.encrypt_centered_to(message, output, rng),
        };
        // Compare identical randomness across the small domain, including the
        // centered sign boundary, then overwrite the last ciphertext with zero.
        for message in (0..limit).chain([0]) {
            let expected = encrypt(message, &mut expected_rng).unwrap();
            let (result, allocation) =
                allocations::measure(|| encrypt_to(message, &mut output, &mut rng));
            result.unwrap();
            assert_eq!(allocation.count, 0, "client encryption must not allocate");
            assert_eq!(output, expected);
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
            assert_eq!(decryptor.decrypt(&output).unwrap(), message);
        }
        let padded_error = matches!(encoding, Encoding::Padded)
            .then_some((limit, TfheClientError::MessageOutsidePaddedDomain));
        for (message, error) in [(t, TfheClientError::MessageOutOfRange)]
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
                Err(TfheClientError::CiphertextDimensionMismatch {
                    expected: dimension,
                    actual
                })
            );
            assert_eq!(wrong, before);
            assert_eq!(rng.next_u64(), expected_rng.next_u64());
        }
    }
}
