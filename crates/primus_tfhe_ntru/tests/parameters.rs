use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_tfhe_ntru::{DecompositionConfig, TfheConfig, TfheParameterError, TfheParameters};
use std::error::Error;

const N: usize = 256;
const Q: u32 = 132_120_577;
const DECOMPOSITION: DecompositionConfig = DecompositionConfig {
    log_basis: 6,
    level_count: None,
};

#[test]
fn independent_domains_and_noise_are_preserved() {
    let config = TfheConfig {
        external_lwe: LweParameters::new(
            N * 2,
            4,
            BarrettModulus::new(65_537),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_modulus: BarrettModulus::new(Q),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 1.25,
        blind_rotation: DecompositionConfig {
            log_basis: 9,
            level_count: Some(3),
        },
        key_switching: DECOMPOSITION,
        key_switching_noise_standard_deviation: 2.5,
    };
    let parameters = TfheParameters::try_from_config(config.clone()).unwrap();
    assert_eq!(parameters.poly_length(), N);
    assert_eq!(parameters.external_lwe_dimension(), N * 2);
    assert_eq!(
        parameters.accumulator_ntru().cipher_modulus_value(),
        Some(Q)
    );
    assert_eq!(
        parameters.external_lwe().cipher_modulus_value(),
        Some(65_537)
    );
    assert_eq!(parameters.key_switching_basis().modulus(), Some(65_537));
    assert_eq!(
        parameters.accumulator_ntru().secret_key_distr(),
        SecretKeyDistr::SparseTernary
    );
    assert_eq!(
        parameters.key_switching_lwe().secret_key_distr(),
        SecretKeyDistr::UniformBinary
    );
    assert_eq!(parameters.external_lwe().noise_standard_deviation(), 0.7);
    assert_eq!(
        parameters
            .accumulator_ntru()
            .noise_distribution()
            .standard_deviation(),
        1.25
    );
    assert_eq!(
        parameters.key_switching_lwe().noise_standard_deviation(),
        2.5
    );
    for blind_rotation in [true, false] {
        let mut invalid = config.clone();
        let decomposition = if blind_rotation {
            &mut invalid.blind_rotation
        } else {
            &mut invalid.key_switching
        };
        decomposition.level_count = Some(0);
        let error = TfheParameters::try_from_config(invalid).err().unwrap();
        match error {
            TfheParameterError::BootstrappingParameters(_) if blind_rotation => assert!(
                error
                    .source()
                    .unwrap()
                    .is::<primus_ntru::NlevParameterError>()
            ),
            TfheParameterError::KeySwitchingParameters(_) if !blind_rotation => assert!(
                error
                    .source()
                    .unwrap()
                    .is::<primus_decompose::ApproxSignedBasisError>()
            ),
            _ => panic!("unexpected parameter error: {error}"),
        }
    }
}

#[test]
fn external_control_domain_and_common_plaintext_are_checked() {
    let modulus = NativeModulus::<u32>::new();
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::ternary(0.2, 0.3),
        SecretKeyDistr::fixed_hamming_weight_ternary(N, 7),
        SecretKeyDistr::fixed_composition_ternary(N, 3, 4),
        SecretKeyDistr::gaussian(3.2),
    ] {
        let external = LweParameters::new(N, 4, BarrettModulus::new(65_537), distr, 0.7);
        let result = TfheParameters::try_new(
            external,
            NlevParameters::with_ntru_params(&accumulator, 9, None),
            DECOMPOSITION,
            0.7,
        );
        if distr.is_binary() || distr.is_ternary() {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.err(),
                Some(TfheParameterError::UnsupportedClientSecretKeyDistribution)
            );
        }
    }
    let external = LweParameters::new(1, 8, modulus, SecretKeyDistr::UniformBinary, 0.7);
    assert_eq!(
        TfheParameters::try_new(
            external,
            NlevParameters::with_ntru_params(&accumulator, 9, None),
            DECOMPOSITION,
            0.7
        )
        .err(),
        Some(TfheParameterError::PlainModulusMismatch)
    );
}

#[test]
fn rotation_domain_must_be_representable_by_input_coefficients() {
    let modulus = NativeModulus::<u16>::new();
    for (log_n, expected) in [
        (14, None),
        (15, Some(TfheParameterError::RotationDomainTooLarge)),
        (16, Some(TfheParameterError::RotationDomainTooLarge)),
    ] {
        let external = LweParameters::new(1, 2, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let ring = NtruParameters::new(1 << log_n, 2, modulus, SecretKeyDistr::UniformBinary, 0.7);
        assert_eq!(
            TfheParameters::try_new(
                external,
                NlevParameters::with_ntru_params(&ring, 4, None),
                DECOMPOSITION,
                0.7
            )
            .err(),
            expected
        );
    }
}
