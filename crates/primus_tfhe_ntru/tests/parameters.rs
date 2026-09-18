use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru::{DecompositionConfig, TfheConfig, TfheParameterError, TfheParameters};
use std::error::Error;

const N: usize = 256;
const Q: u32 = 132_120_577;

#[test]
fn config_derives_domains_and_keeps_key_switch_noise_independent() {
    let config = TfheConfig {
        external_lwe: LweParameters::new(
            8,
            4,
            BarrettModulus::new(Q),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 1.25,
        blind_rotation: DecompositionConfig {
            log_basis: 9,
            level_count: Some(3),
        },
        key_switching: DecompositionConfig {
            log_basis: 6,
            level_count: Some(4),
        },
        key_switching_noise_standard_deviation: 2.5,
    };
    let parameters = TfheParameters::try_from_config(config.clone()).unwrap();
    let accumulator = parameters.accumulator_ntru();
    let client = parameters.ntru_key_switching().ntru();
    for ring in [accumulator, client] {
        assert_eq!(ring.poly_length(), N);
        assert_eq!(ring.cipher_modulus_value(), Some(Q));
        assert_eq!(ring.plain_modulus(), 4);
    }
    assert_eq!(
        accumulator.secret_key_distr(),
        SecretKeyDistr::SparseTernary
    );
    assert_eq!(client.secret_key_distr(), SecretKeyDistr::UniformBinary);
    assert_eq!(accumulator.noise_distribution().standard_deviation(), 1.25);
    assert_eq!(client.noise_distribution().standard_deviation(), 2.5);
    assert_eq!(parameters.blind_rotation().basis().log_basis(), 9);
    assert_eq!(parameters.ntru_key_switching().basis().log_basis(), 6);
    for blind_rotation in [true, false] {
        let mut invalid = config.clone();
        let decomposition = if blind_rotation {
            &mut invalid.blind_rotation
        } else {
            &mut invalid.key_switching
        };
        decomposition.level_count = Some(0);
        let error = TfheParameters::try_from_config(invalid).err().unwrap();
        assert!(matches!(
            (&error, blind_rotation),
            (TfheParameterError::BootstrappingParameters(_), true)
                | (TfheParameterError::KeySwitchingParameters(_), false)
        ));
        assert!(
            error
                .source()
                .unwrap()
                .is::<primus_ntru::NlevParameterError>()
        );
    }
}

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
    let accumulator = ntru(N, 4, Q, SecretKeyDistr::SparseTernary);
    let nonbinary_client = ntru(N, 4, Q, SecretKeyDistr::SparseTernary);
    let external = LweParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    assert_eq!(
        TfheParameters::try_new(external, nlev(&accumulator), nlev(&nonbinary_client)).err(),
        Some(TfheParameterError::ClientSecretKeyMustBeBinary)
    );

    let client = ntru(N, 4, Q, SecretKeyDistr::UniformBinary);
    let smaller_dimension =
        LweParameters::new(N / 2, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    assert!(TfheParameters::try_new(smaller_dimension, nlev(&accumulator), nlev(&client)).is_ok());

    let wrong_dimension = LweParameters::new(N * 2, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    assert_eq!(
        TfheParameters::try_new(wrong_dimension, nlev(&accumulator), nlev(&client)).err(),
        Some(TfheParameterError::InvalidLweDimension {
            lwe_dimension: N * 2,
            poly_length: N,
        })
    );
}

#[test]
fn rejects_mismatched_ring_or_plaintext_domains() {
    let external = LweParameters::new(
        N,
        4,
        BarrettModulus::new(Q),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let accumulator = ntru(N, 4, Q, SecretKeyDistr::SparseTernary);
    let wrong_length = ntru(N * 2, 4, Q, SecretKeyDistr::UniformBinary);
    assert_eq!(
        TfheParameters::try_new(external, nlev(&accumulator), nlev(&wrong_length)).err(),
        Some(TfheParameterError::PolynomialLengthMismatch)
    );

    let external = LweParameters::new(
        N,
        4,
        BarrettModulus::new(Q),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let wrong_plain = ntru(N, 8, Q, SecretKeyDistr::UniformBinary);
    assert_eq!(
        TfheParameters::try_new(external, nlev(&accumulator), nlev(&wrong_plain)).err(),
        Some(TfheParameterError::PlainModulusMismatch)
    );

    let external = LweParameters::new(
        N,
        4,
        BarrettModulus::new(Q),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let wrong_modulus = ntru(N, 4, 998_244_353, SecretKeyDistr::UniformBinary);
    assert_eq!(
        TfheParameters::try_new(external, nlev(&accumulator), nlev(&wrong_modulus)).err(),
        Some(TfheParameterError::CipherModulusMismatch)
    );
}

#[test]
fn rotation_domain_must_be_representable_by_input_coefficients() {
    let modulus = primus_modulus::NativeModulus::<u16>::new();
    for (log_n, expected) in [
        (14, None),
        (15, Some(TfheParameterError::RotationDomainTooLarge)),
        (16, Some(TfheParameterError::RotationDomainTooLarge)),
    ] {
        let external = LweParameters::new(1, 2, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let ring = NtruParameters::new(1 << log_n, 2, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let gadget = NlevParameters::with_ntru_params(&ring, 4, None);
        assert_eq!(
            TfheParameters::try_new(external, gadget.clone(), gadget).err(),
            expected,
        );
    }
}
