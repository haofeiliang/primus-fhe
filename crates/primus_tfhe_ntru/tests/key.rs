use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_tfhe_ntru::{
    NtruClientError, NtruClientKey, NtruDecryptor, NtruEncryptor, NtruKeyError, NtruTfheParameters,
};

const N: usize = 8;
const LWE_DIMENSION: usize = 4;

fn parameters() -> NtruTfheParameters<u32, NativeModulus<u32>> {
    let modulus = NativeModulus::new();
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::gaussian(3.2), 0.7);
    NtruTfheParameters::try_new(
        LweParameters::new(
            LWE_DIMENSION,
            4,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&accumulator, 8, None),
        NlevParameters::with_ntru_params(&client, 8, None),
    )
    .unwrap()
}

fn imported_key(client: [i32; N]) -> NtruClientKey<u32> {
    // General NTRU secrets and the accumulator retain nonbinary coefficients.
    let accumulator =
        NtruSecretKey::new(vec![2, 1, 0, 0, 0, 0, 0, 0], SecretKeyDistr::gaussian(3.2));
    NtruClientKey::new(
        NtruSecretKey::new(client.to_vec(), SecretKeyDistr::UniformBinary),
        accumulator,
        LWE_DIMENSION,
    )
}

#[test]
fn imported_client_coefficients_must_be_binary_and_zero_padded() {
    let parameters = parameters();
    let binary = imported_key([1, 0, 1, 1, 0, 0, 0, 0]);
    assert_eq!(binary.check_compatible(&parameters), Ok(()));
    assert!(NtruEncryptor::new(&parameters, &binary).is_ok());
    assert!(NtruDecryptor::new(&parameters, &binary).is_ok());

    // f = 2 + X is invertible over the native ring (f(1) is odd), but its
    // binary distribution label cannot make it a valid blind-rotation control.
    for (coefficients, expected) in [
        (
            [2, 1, 0, 0, 0, 0, 0, 0],
            NtruKeyError::ClientSecretKeyMustBeBinary,
        ),
        (
            [1, 0, 0, -1, 0, 0, 0, 0],
            NtruKeyError::ClientSecretKeyMustBeBinary,
        ),
        (
            [1, 0, 1, 1, 0, 0, 0, 1],
            NtruKeyError::ClientSecretKeyPaddingMismatch,
        ),
    ] {
        let key = imported_key(coefficients);
        assert_eq!(key.check_compatible(&parameters), Err(expected.clone()));
        assert_eq!(
            NtruEncryptor::new(&parameters, &key).err(),
            Some(NtruClientError::IncompatibleKey(expected.clone()))
        );
        assert_eq!(
            NtruDecryptor::new(&parameters, &key).err(),
            Some(NtruClientError::IncompatibleKey(expected))
        );
    }
}
