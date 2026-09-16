use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_tfhe_ntru::{
    NtruClientError, NtruClientKey, NtruDecryptor, NtruEncryptor, NtruKeyError, NtruTfheParameters,
};

const N: usize = 8;
const LWE_DIMENSION: usize = 4;

fn parameters() -> NtruTfheParameters<u32, NativeModulus<u32>> {
    parameters_with_plaintext(4)
}

fn parameters_with_plaintext(t: u32) -> NtruTfheParameters<u32, NativeModulus<u32>> {
    let modulus = NativeModulus::new();
    let client = NtruParameters::new(N, t, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, t, modulus, SecretKeyDistr::gaussian(3.2), 0.7);
    NtruTfheParameters::try_new(
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
    assert!(NtruEncryptor::try_new(&parameters, &binary).is_ok());
    assert!(NtruDecryptor::try_new(&parameters, &binary).is_ok());

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
            NtruEncryptor::try_new(&parameters, &key).err(),
            Some(NtruClientError::IncompatibleKey(expected.clone()))
        );
        assert_eq!(
            NtruDecryptor::try_new(&parameters, &key).err(),
            Some(NtruClientError::IncompatibleKey(expected))
        );
    }
}

#[test]
fn padded_client_domain_matches_odd_and_even_lut_domains() {
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(0x5041_4444_4544);
    let key = imported_key([1, 0, 1, 1, 0, 0, 0, 0]);
    for t in [3u32, 4, 5] {
        let parameters = parameters_with_plaintext(t);
        let encryptor = NtruEncryptor::try_new(&parameters, &key).unwrap();
        let decryptor = NtruDecryptor::try_new(&parameters, &key).unwrap();
        let domain_len = t.div_ceil(2);
        assert!(
            parameters
                .compile_lookup_table_slice(&vec![0; domain_len as usize])
                .is_ok()
        );
        let input = encryptor.encrypt_padded(domain_len - 1, &mut rng).unwrap();
        assert_eq!(decryptor.decrypt(&input).unwrap(), domain_len - 1);
        assert_eq!(
            encryptor.encrypt_padded(domain_len, &mut rng).unwrap_err(),
            NtruClientError::MessageOutsidePaddedDomain
        );
        if t == 4 {
            // Callers supply D*k values; the compiler owns the padding to D*s.
            assert_eq!(
                parameters
                    .compile_interleaved_lookup_table_slice(3, &[0; 8])
                    .unwrap_err(),
                primus_tfhe_ntru::LookupTableError::DomainLengthMismatch {
                    expected: 6,
                    actual: 8
                }
            );
        }
        assert_eq!(
            parameters
                .compile_interleaved_lookup_table_slice(usize::MAX, &[])
                .unwrap_err(),
            primus_tfhe_ntru::LookupTableError::ManyTableLengthOverflow
        );
    }
}
