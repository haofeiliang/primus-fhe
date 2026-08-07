use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru::{NtruParameterError, NtruTfheParameters};

const N: usize = 256;
const Q: u32 = 132_120_577;

fn ntru(
    poly_length: usize,
    plain_modulus: u32,
    cipher_modulus: u32,
    distr: SecretKeyDistr,
) -> NtruParameters<u32, BarrettModulus<u32>> {
    NtruParameters::new(
        poly_length,
        plain_modulus,
        BarrettModulus::new(cipher_modulus),
        distr,
        0.7,
    )
}

fn nlev(
    parameters: &NtruParameters<u32, BarrettModulus<u32>>,
) -> NlevParameters<u32, BarrettModulus<u32>> {
    NlevParameters::with_ntru_params(parameters, 9, None)
}

#[test]
fn accepts_a_smaller_external_dimension_and_rejects_an_oversized_one() {
    let modulus = BarrettModulus::new(Q);
    let accumulator = ntru(N, 4, Q, SecretKeyDistr::Ternary);
    let nonbinary_client = ntru(N, 4, Q, SecretKeyDistr::Ternary);
    let external = LweParameters::new(N, 4, modulus, SecretKeyDistr::Binary, 0.7);
    assert_eq!(
        NtruTfheParameters::try_new(external, nlev(&accumulator), nlev(&nonbinary_client)).err(),
        Some(NtruParameterError::ClientSecretKeyMustBeBinary)
    );

    let client = ntru(N, 4, Q, SecretKeyDistr::Binary);
    let smaller_dimension = LweParameters::new(N / 2, 4, modulus, SecretKeyDistr::Binary, 0.7);
    assert!(
        NtruTfheParameters::try_new(smaller_dimension, nlev(&accumulator), nlev(&client)).is_ok()
    );

    let wrong_dimension = LweParameters::new(N * 2, 4, modulus, SecretKeyDistr::Binary, 0.7);
    assert_eq!(
        NtruTfheParameters::try_new(wrong_dimension, nlev(&accumulator), nlev(&client)).err(),
        Some(NtruParameterError::InvalidLweDimension {
            lwe_dimension: N * 2,
            poly_length: N,
        })
    );

    let zero_dimension = LweParameters::new(0, 4, modulus, SecretKeyDistr::Binary, 0.7);
    assert_eq!(
        NtruTfheParameters::try_new(zero_dimension, nlev(&accumulator), nlev(&client)).err(),
        Some(NtruParameterError::InvalidLweDimension {
            lwe_dimension: 0,
            poly_length: N,
        })
    );
}

#[test]
fn rejects_mismatched_ring_or_plaintext_domains() {
    let external = LweParameters::new(N, 4, BarrettModulus::new(Q), SecretKeyDistr::Binary, 0.7);
    let accumulator = ntru(N, 4, Q, SecretKeyDistr::Ternary);
    let wrong_length = ntru(N * 2, 4, Q, SecretKeyDistr::Binary);
    assert_eq!(
        NtruTfheParameters::try_new(external, nlev(&accumulator), nlev(&wrong_length)).err(),
        Some(NtruParameterError::PolynomialLengthMismatch)
    );

    let external = LweParameters::new(N, 4, BarrettModulus::new(Q), SecretKeyDistr::Binary, 0.7);
    let wrong_plain = ntru(N, 8, Q, SecretKeyDistr::Binary);
    assert_eq!(
        NtruTfheParameters::try_new(external, nlev(&accumulator), nlev(&wrong_plain)).err(),
        Some(NtruParameterError::PlainModulusMismatch)
    );

    let external = LweParameters::new(N, 4, BarrettModulus::new(Q), SecretKeyDistr::Binary, 0.7);
    let wrong_modulus = ntru(N, 4, 998_244_353, SecretKeyDistr::Binary);
    assert_eq!(
        NtruTfheParameters::try_new(external, nlev(&accumulator), nlev(&wrong_modulus)).err(),
        Some(NtruParameterError::CipherModulusMismatch)
    );
}
