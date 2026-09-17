use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_tfhe_ntru::{
    ClientKey, Decryptor, Encryptor, TfheClientError, TfheKeyError, TfheParameters,
};

const N: usize = 8;
const LWE_DIMENSION: usize = 4;

fn parameters() -> TfheParameters<u32, NativeModulus<u32>> {
    let t = 4;
    let modulus = NativeModulus::new();
    let client = NtruParameters::new(N, t, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, t, modulus, SecretKeyDistr::gaussian(3.2), 0.7);
    TfheParameters::try_new(
        LweParameters::new(
            LWE_DIMENSION,
            t,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&accumulator, 8, None),
        NlevParameters::with_ntru_params(&client, 8, None),
    )
    .unwrap()
}

fn imported_key(client: [i32; N]) -> ClientKey<u32> {
    // General NTRU secrets and the accumulator retain nonbinary coefficients.
    let accumulator =
        NtruSecretKey::new(vec![2, 1, 0, 0, 0, 0, 0, 0], SecretKeyDistr::gaussian(3.2));
    ClientKey::new(
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
    assert!(Encryptor::try_new(&parameters, &binary).is_ok());
    assert!(Decryptor::try_new(&parameters, &binary).is_ok());

    // f = 2 + X is invertible over the native ring (f(1) is odd), but its
    // binary distribution label cannot make it a valid blind-rotation control.
    for (coefficients, expected) in [
        (
            [2, 1, 0, 0, 0, 0, 0, 0],
            TfheKeyError::ClientSecretKeyMustBeBinary,
        ),
        (
            [1, 0, 0, -1, 0, 0, 0, 0],
            TfheKeyError::ClientSecretKeyMustBeBinary,
        ),
        (
            [1, 0, 1, 1, 0, 0, 0, 1],
            TfheKeyError::ClientSecretKeyPaddingMismatch,
        ),
    ] {
        let key = imported_key(coefficients);
        assert_eq!(key.check_compatible(&parameters), Err(expected.clone()));
        assert_eq!(
            Encryptor::try_new(&parameters, &key).err(),
            Some(TfheClientError::IncompatibleKey(expected.clone()))
        );
        assert_eq!(
            Decryptor::try_new(&parameters, &key).err(),
            Some(TfheClientError::IncompatibleKey(expected))
        );
    }
}
