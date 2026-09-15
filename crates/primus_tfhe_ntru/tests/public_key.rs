use primus_lwe::{LweParameters, LwePublicKey, LweSecretKey};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_reduce::RingContext;
use primus_tfhe_ntru::{
    NtruClientError, NtruClientKey, NtruDecryptor, NtruEncryptor, NtruKeyError, NtruTfheParameters,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

fn check<M: RingContext<u32>>(modulus: M) {
    let ring = NtruParameters::new(8, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let params = NtruTfheParameters::try_new(
        LweParameters::new(4, 4, modulus, SecretKeyDistr::UniformBinary, 0.7),
        NlevParameters::with_ntru_params(&ring, 8, None),
        NlevParameters::with_ntru_params(&ring, 8, None),
    )
    .unwrap();
    let client = NtruClientKey::new(
        NtruSecretKey::new(vec![1, 0, 1, 1, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        NtruSecretKey::new(vec![1, 0, 0, 0, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        4,
    );
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_504b);
    let public = client.try_generate_public_key(&params, &mut rng).unwrap();
    assert_eq!(public.dimension(), 4); // Active prefix, not the full ring length.
    let encryptor = NtruEncryptor::try_new(&params, &public).unwrap();
    let decryptor = NtruDecryptor::try_new(&params, &client).unwrap();
    for message in 0..4u32 {
        for ciphertext in [
            encryptor.encrypt(message, &mut rng).unwrap(),
            encryptor.encrypt_centered(message, &mut rng).unwrap(),
        ] {
            assert_eq!(decryptor.decrypt::<u32>(&ciphertext).unwrap(), message);
        }
        if message < 2 {
            let ciphertext = encryptor.encrypt_padded(message, &mut rng).unwrap();
            assert_eq!(decryptor.decrypt::<u32>(&ciphertext).unwrap(), message);
        }
    }
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected_rng = StdRng::seed_from_u64(seed);
    assert_eq!(
        encryptor.encrypt(u64::MAX, &mut rng).unwrap_err(),
        NtruClientError::MessageConversion
    );
    assert_eq!(
        encryptor.encrypt(4u32, &mut rng).unwrap_err(),
        NtruClientError::MessageOutOfRange
    );
    assert_eq!(
        encryptor.encrypt_centered(4u32, &mut rng).unwrap_err(),
        NtruClientError::MessageOutOfRange
    );
    assert_eq!(
        encryptor.encrypt_padded(2u32, &mut rng).unwrap_err(),
        NtruClientError::MessageOutsidePaddedDomain
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
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
        NtruEncryptor::try_new(&params, &foreign).err(),
        Some(NtruClientError::PublicKeyModulusMismatch)
    );
    let full_params = LweParameters::new(8, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let full_secret = LweSecretKey::generate(&full_params, &mut rng);
    let full = LwePublicKey::generate(full_secret.as_view(), &full_params, &mut rng);
    assert_eq!(
        NtruEncryptor::try_new(&params, &full).err(),
        Some(NtruClientError::PublicKeyDimensionMismatch {
            expected: 4,
            actual: 8
        })
    );
    let bad_client = NtruClientKey::new(
        NtruSecretKey::new(vec![1, -1, 1, 1, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        NtruSecretKey::new(vec![1, 0, 0, 0, 0, 0, 0, 0], SecretKeyDistr::UniformBinary),
        4,
    );
    let seed = rng.next_u64();
    let mut rng = StdRng::seed_from_u64(seed);
    let mut expected_rng = StdRng::seed_from_u64(seed);
    assert_eq!(
        bad_client.try_generate_public_key(&params, &mut rng).err(),
        Some(NtruKeyError::ClientSecretKeyMustBeBinary)
    );
    assert_eq!(rng.next_u64(), expected_rng.next_u64());
}

#[test]
fn public_clients_use_only_the_binary_prefix_and_reject_incompatible_keys() {
    check(NativeModulus::new());
    check(BarrettModulus::new(132_120_577));
}
