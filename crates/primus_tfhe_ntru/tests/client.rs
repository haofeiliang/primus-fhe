use primus_lwe::{LweCiphertext, LweParameters, LwePublicKey, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_test_allocations as allocations;
use primus_tfhe_ntru::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, ClientKey, Decryptor, EncryptionKey,
    Encryptor, TfheClientError, TfheKeyError, TfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn check<M: RingContext<u32>>(modulus: M, plain_modulus: u32) {
    let ring = NtruParameters::new(
        8,
        plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        1.4,
    );
    let params = TfheParameters::try_new(
        LweParameters::new(
            4,
            plain_modulus,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&ring, 8, None),
        NlevParameters::with_ntru_params(&ring, 8, None),
    )
    .unwrap();
    let client = ClientKey::new(
        NtruSecretKey::new(vec![1, 0, 1, 1, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        NtruSecretKey::new(vec![1, 0, 0, 0, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        4,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_504b);
    let public = client.try_generate_public_key(&params, &mut rng).unwrap();
    assert_eq!(public.dimension(), 4); // Active prefix, not the full ring length.
    check_reused_output(&params, &client, &public);
    check_reused_output(&params, &client, &client);
    check_boolean_errors(&params, &client);

    let foreign_params = LweParameters::new(
        4,
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
    let full_params = LweParameters::new(8, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let full_secret = LweSecretKey::generate(&full_params, &mut rng);
    let full = LwePublicKey::generate(full_secret.as_view(), &full_params, &mut rng);
    assert_eq!(
        Encryptor::try_new(&params, &full).err(),
        Some(TfheClientError::PublicKeyDimensionMismatch {
            expected: 4,
            actual: 8
        })
    );
    let bad_client = ClientKey::new(
        NtruSecretKey::new(vec![1, -1, 1, 1, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        NtruSecretKey::new(vec![1, 0, 0, 0, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        4,
    );
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected_rng = StdRng::seed_from_u64(seed);
    assert_eq!(
        bad_client.try_generate_public_key(&params, &mut rng).err(),
        Some(TfheKeyError::InvalidClientSecretKeyCoefficient)
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
}

fn check_boolean_errors<M: RingContext<u32>>(
    parameters: &TfheParameters<u32, M>,
    client: &ClientKey<u32>,
) {
    if parameters.plain_modulus_value() != 4 {
        assert_eq!(
            BooleanEncryptor::try_new(parameters, client).err(),
            Some(BooleanError::PlaintextModulusMustBeFour)
        );
        assert_eq!(
            BooleanDecryptor::try_new(parameters, client).err(),
            Some(BooleanError::PlaintextModulusMustBeFour)
        );
        return;
    }
    let encryptor = BooleanEncryptor::try_new(parameters, client).unwrap();
    let decryptor = BooleanDecryptor::try_new(parameters, client).unwrap();
    let raw_encryptor = Encryptor::try_new(parameters, client).unwrap();
    let mut rng = StdRng::seed_from_u64(0xB202);
    for message in [2, 3] {
        let invalid = raw_encryptor.encrypt(message, &mut rng).unwrap();
        assert_eq!(
            decryptor.decrypt(&invalid),
            Err(BooleanError::InvalidPlaintext)
        );
    }
    let dimension = parameters.external_lwe_dimension();
    let mut wrong = LweCiphertext::new(vec![1; dimension]);
    let before = wrong.clone();
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected_rng = StdRng::seed_from_u64(seed);
    let error = BooleanError::Client(TfheClientError::CiphertextDimensionMismatch {
        expected: dimension,
        actual: dimension - 1,
    });
    assert_eq!(
        encryptor.encrypt_to(true, &mut wrong, &mut rng),
        Err(error.clone())
    );
    assert_eq!(wrong, before);
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
    assert_eq!(decryptor.decrypt(&wrong), Err(error));
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
