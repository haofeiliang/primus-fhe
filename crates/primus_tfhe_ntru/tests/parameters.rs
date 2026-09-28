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

#[test]
fn configs_return_accumulator_return_key_and_cbs_errors() {
    use primus_ntru::NtruParameterError;
    use primus_tfhe_ntru::{
        CircuitBootstrapConfig, CircuitBootstrapParameterError, CircuitBootstrapParameters,
    };
    let basis = DecompositionConfig {
        log_basis: 4,
        level_count: Some(1),
    };
    let config = TfheConfig {
        external_lwe: LweParameters::new(
            4,
            4u32,
            primus_modulus::PowOf2Modulus::new(256),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_modulus: BarrettModulus::new(257),
        poly_length: 8,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: basis,
        key_switching: basis,
        key_switching_noise_standard_deviation: 0.7,
    };
    let tfhe = TfheParameters::try_from_config(config.clone()).unwrap();
    let mut invalid = config.clone();
    invalid.poly_length = 3;
    assert!(matches!(
        TfheParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::InvalidPolynomialLength
        ))
    ));
    let mut invalid = config.clone();
    invalid.accumulator_noise_standard_deviation = f64::NAN;
    assert!(matches!(
        TfheParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::Noise(_)
        ))
    ));
    let mut invalid = config.clone();
    invalid.accumulator_modulus = BarrettModulus::new(3);
    assert!(matches!(
        TfheParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::Encoding(_)
        ))
    ));
    let mut invalid = config.clone();
    invalid.accumulator_secret_key_distr =
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 9 };
    assert!(matches!(
        TfheParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::SecretKey(_)
        ))
    ));
    let mut invalid = config;
    invalid.key_switching_noise_standard_deviation = 0.0;
    assert!(matches!(
        TfheParameters::try_from_config(invalid),
        Err(TfheParameterError::KeySwitchingEncryption(
            primus_lwe::LweParameterError::Noise(_)
        ))
    ));

    let cbs = CircuitBootstrapConfig {
        output: basis,
        trace: basis,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: basis,
        scheme_switch_noise_standard_deviation: 0.7,
    };
    assert!(CircuitBootstrapParameters::try_from_config(&tfhe, cbs).is_ok());
    for role in ["trace", "scheme-switch"] {
        let mut invalid = cbs;
        if role == "trace" {
            invalid.trace_noise_standard_deviation = 0.0;
        } else {
            invalid.scheme_switch_noise_standard_deviation = f64::INFINITY;
        }
        let error = CircuitBootstrapParameters::try_from_config(&tfhe, invalid)
            .err()
            .unwrap();
        assert!(matches!(
            &error,
            CircuitBootstrapParameterError::EncryptionParameters { role: actual, source: NtruParameterError::Noise(_) } if *actual == role
        ));
        // Follow a real constructor failure through the public key-generation
        // wrapper. Each frame keeps its role and prints only its own context.
        use std::error::Error;
        let error = primus_tfhe_ntru::KeyGenerationError::from(error);
        assert_eq!(
            error.to_string(),
            format!("invalid circuit-bootstrap {role} encryption parameters")
        );
        let parameters = error.source().unwrap();
        assert!(parameters.is::<NtruParameterError>());
        assert_eq!(parameters.to_string(), "invalid NTRU noise distribution");
        let sampler = parameters.source().unwrap();
        assert!(matches!(
            sampler.downcast_ref::<primus_distr::GaussianError>(),
            Some(primus_distr::GaussianError::InvalidStandardDeviation { .. })
        ));
        assert!(sampler.source().is_none());
    }
}
