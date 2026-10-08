use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationAlgorithm;
use primus_tfhe_ntru::{BlindRotationConfig, LweConfig, PbsConfig, PbsMessageConfig};
use primus_tfhe_ntru::{
    DecompositionConfig, GadgetEncryptionConfig, PbsParameters, TfheParameterError,
};
use std::error::Error;

const N: usize = 32;
const Q: u32 = 132_120_577;
const DECOMPOSITION: DecompositionConfig = DecompositionConfig {
    log_basis: DecompositionBaseLog::new(6),
    level_count: None,
};

#[test]
fn independent_domains_and_noise_are_preserved() {
    let config = PbsConfig {
        blind_rotation: BlindRotationConfig {
            external_lwe: LweConfig {
                dimension: LweDimension::new(N * 2),
                cipher_modulus: BarrettModulus::new(65_537).into(),
                secret_key_distr: SecretKeyDistr::UniformBinary,
                noise_standard_deviation: 0.7,
            },
            acc_modulus: BarrettModulus::new(Q).into(),
            acc_poly_length: PolyLength::new(N),
            bsk_secret_distr: SecretKeyDistr::SparseTernary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(9),
                    level_count: Some(DecompositionLevelCount::new(3)),
                },
                noise_standard_deviation: 1.25,
            },
            algorithm: BlindRotationAlgorithm::Classic,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: DECOMPOSITION,
            noise_standard_deviation: 2.5,
        },
        messages: PbsMessageConfig::new(4),
    };
    let parameters = config.try_prepare().unwrap();
    // Binding ordinary ring messages reuses the gadget's sampler allocation.
    let ordinary = NtruParameters::try_from_nlev(
        parameters.blind_rotation(),
        primus_encoding::ScaledCodec::new(4, parameters.accumulator_ntru().cipher_modulus()),
    )
    .unwrap();
    assert!(std::ptr::eq(
        ordinary.encryption_parameters(),
        parameters.accumulator_ntru()
    ));
    assert_eq!(parameters.poly_length(), PolyLength::new(N));
    assert_eq!(
        parameters.external_lwe_dimension(),
        LweDimension::new(N * 2)
    );
    assert_eq!(
        parameters.accumulator_ntru().cipher_modulus_value(),
        Some(Q)
    );
    assert_eq!(
        parameters.external_lwe().cipher_modulus_value(),
        Some(65_537)
    );
    assert_eq!(
        parameters
            .key_switching_basis()
            .expect("PBS parameters include key switching")
            .modulus(),
        Some(65_537)
    );
    assert_eq!(
        parameters.accumulator_ntru().secret_key_distr(),
        SecretKeyDistr::SparseTernary
    );
    assert_eq!(
        parameters
            .key_switching_lwe()
            .expect("PBS parameters include key switching")
            .secret_key_distr(),
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
        parameters
            .key_switching_lwe()
            .expect("PBS parameters include key switching")
            .noise_standard_deviation(),
        2.5
    );
    for blind_rotation in [true, false] {
        let mut invalid = config;
        let decomposition = if blind_rotation {
            &mut invalid.blind_rotation.bsk_gadget.decomposition
        } else {
            &mut invalid.key_switching.decomposition
        };
        decomposition.level_count = Some(DecompositionLevelCount::new(usize::MAX));
        let error = invalid.try_prepare().err().unwrap();
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
fn external_control_domain_is_checked() {
    let modulus = NativeModulus::<u32>::new();
    let accumulator = NtruParameters::new(
        PolyLength::new(N),
        4,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::ternary(0.2, 0.3),
        SecretKeyDistr::fixed_hamming_weight_ternary(N, 7),
        SecretKeyDistr::fixed_composition_ternary(N, 3, 4),
        SecretKeyDistr::gaussian(3.2),
    ] {
        let external = LweParameters::new(
            LweDimension::new(N),
            4,
            BarrettModulus::new(65_537),
            distr,
            0.7,
        );
        let result = PbsParameters::try_new(
            external.into_encryption_parameters(),
            NlevParameters::try_with_basis(
                &accumulator,
                ApproxSignedBasis::new(
                    accumulator.cipher_modulus_value(),
                    DecompositionBaseLog::new(9),
                    None,
                ),
            )
            .unwrap(),
            GadgetEncryptionConfig {
                decomposition: DECOMPOSITION,
                noise_standard_deviation: 0.7,
            },
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
}

#[test]
fn rotation_domain_must_be_representable_by_input_coefficients() {
    let modulus = NativeModulus::<u16>::new();
    for (log_n, expected) in [
        (14, None),
        (15, Some(TfheParameterError::RotationDomainTooLarge)),
        (16, Some(TfheParameterError::RotationDomainTooLarge)),
    ] {
        let external = LweParameters::new(
            LweDimension::new(1),
            2,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let ring = NtruParameters::new(
            PolyLength::new(1 << log_n),
            2,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        assert_eq!(
            PbsParameters::try_new(
                external.into_encryption_parameters(),
                NlevParameters::try_with_basis(
                    &ring,
                    ApproxSignedBasis::new(
                        ring.cipher_modulus_value(),
                        DecompositionBaseLog::new(4),
                        None
                    )
                )
                .unwrap(),
                GadgetEncryptionConfig {
                    decomposition: DECOMPOSITION,
                    noise_standard_deviation: 0.7,
                }
            )
            .err(),
            expected
        );
    }
}

#[test]
fn configs_return_accumulator_and_return_key_errors() {
    use primus_ntru::NtruParameterError;
    let basis = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: Some(DecompositionLevelCount::new(1)),
    };
    let config = PbsConfig {
        blind_rotation: BlindRotationConfig {
            external_lwe: LweConfig {
                dimension: LweDimension::new(4),
                cipher_modulus: primus_modulus::PowOf2Modulus::new(256u32).into(),
                secret_key_distr: SecretKeyDistr::UniformBinary,
                noise_standard_deviation: 0.7,
            },
            acc_modulus: BarrettModulus::new(257).into(),
            acc_poly_length: PolyLength::new(32),
            bsk_secret_distr: SecretKeyDistr::SparseTernary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: basis,
                noise_standard_deviation: 0.7,
            },
            algorithm: BlindRotationAlgorithm::Classic,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        messages: PbsMessageConfig::new(4),
    };
    let mut invalid = config;
    invalid.blind_rotation.bsk_gadget.noise_standard_deviation = f64::NAN;
    assert!(matches!(
        invalid.try_prepare(),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::Noise(_)
        ))
    ));
    let mut invalid = config;
    invalid.blind_rotation.bsk_secret_distr =
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 33 };
    assert!(matches!(
        invalid.try_prepare(),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::SecretKey(_)
        ))
    ));
    let mut invalid = config;
    invalid.key_switching.noise_standard_deviation = 0.0;
    assert!(matches!(
        invalid.try_prepare(),
        Err(TfheParameterError::KeySwitchingEncryption(
            primus_lwe::LweParameterError::Noise(_)
        ))
    ));
}

// These constructors do not depend on a transform table or encrypted keys.
fn check_circuit_parameters<M: primus_reduce::RingContext<u64>>(
    modulus: M,
    foreign_modulus: Option<M>,
) {
    use primus_tfhe_ntru::{
        CbsGadgetConfig, CbsParameters, CircuitBootstrapParameterError as Error,
    };
    let make = |plain| {
        let acc = NtruParameters::new(
            PolyLength::new(N),
            plain,
            modulus,
            SecretKeyDistr::SparseTernary,
            0.7,
        );

        PbsParameters::try_new(
            LweEncryptionParameters::new(
                LweDimension::new(16),
                modulus,
                SecretKeyDistr::UniformBinary,
                0.7,
            ),
            NlevParameters::try_with_basis(
                &acc,
                ApproxSignedBasis::new(
                    acc.cipher_modulus_value(),
                    DecompositionBaseLog::new(10),
                    None,
                ),
            )
            .unwrap(),
            GadgetEncryptionConfig {
                decomposition: primus_tfhe_ntru::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(10),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
        )
        .unwrap()
    };
    let tfhe = make(N as u64); // Only two interleaved outputs fit this domain.
    let config = CbsGadgetConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(2)),
        },
        trace: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(9),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        scheme_switch: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(4)),
        },
    };
    let configured = CbsParameters::try_from_config(&tfhe, config).unwrap();
    assert_eq!(configured.poly_length(), tfhe.poly_length());
    assert_eq!(configured.trace().basis().log_basis().get(), 9);
    assert_eq!(configured.trace().basis().decompose_length().get(), 3);
    assert_eq!(configured.scheme_switch().basis().log_basis().get(), 10);
    assert_eq!(
        configured.scheme_switch().basis().decompose_length().get(),
        4
    );
    // Both bases retain the accumulator's exact sampler state and noise.
    for parameters in [configured.trace(), configured.scheme_switch()] {
        assert!(std::ptr::eq(
            parameters.encryption_parameters(),
            tfhe.accumulator_ntru(),
        ));
        assert_eq!(
            parameters
                .encryption_parameters()
                .noise_distribution()
                .standard_deviation(),
            0.7,
        );
    }
    assert_eq!(configured.trace().nlev_len(), N * 3);
    assert_eq!(configured.scheme_switch().nlev_len(), N * 4);
    assert_eq!(configured.output_nlev_len(), N * 2);
    for role in ["output", "trace", "scheme-switch"] {
        let mut invalid = config;
        match role {
            "output" => invalid.output.level_count = Some(DecompositionLevelCount::new(usize::MAX)),
            "trace" => invalid.trace.level_count = Some(DecompositionLevelCount::new(usize::MAX)),
            _ => invalid.scheme_switch.level_count = Some(DecompositionLevelCount::new(usize::MAX)),
        }
        let error = CbsParameters::try_from_config(&tfhe, invalid)
            .err()
            .unwrap();
        match role {
            "output" => assert!(matches!(error, Error::InvalidOutputBasis(_))),
            _ => assert!(
                matches!(error, Error::GadgetParameters { role: actual, .. } if actual == role)
            ),
        }
    }
    let trace = tfhe.blind_rotation().clone();
    let output = |levels| {
        ApproxSignedBasis::new(
            modulus.explicit_value(),
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(levels)),
        )
    };
    assert!(CbsParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone()).is_ok());
    // Capacity depends on the input encoding, so reject when compiling the
    // CBS program; the same key parameters accept a smaller plaintext domain.
    let cbs = CbsParameters::try_new(&tfhe, output(3), trace.clone(), trace.clone()).unwrap();
    let crowded = RoundedCodec::new(N as u64, modulus);
    assert!(cbs.compile_lookup_table(&crowded).is_err());
    let fitting = RoundedCodec::new(4, modulus);
    assert!(cbs.compile_lookup_table(&fitting).is_ok());
    let foreign_ring = NtruParameters::new(
        PolyLength::new(N * 2),
        4,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let foreign_modulus = foreign_modulus.map(|modulus| {
        NtruParameters::new(
            PolyLength::new(N),
            4,
            modulus,
            SecretKeyDistr::SparseTernary,
            0.7,
        )
    });
    for foreign in std::iter::once(&foreign_ring).chain(foreign_modulus.as_ref()) {
        assert!(matches!(
            CbsParameters::try_new(
                &tfhe,
                output(2),
                NlevParameters::with_ntru_params(
                    foreign,
                    DecompositionBaseLog::new(8),
                    Some(DecompositionLevelCount::new(2))
                ),
                trace.clone()
            ),
            Err(Error::PolynomialLengthMismatch { role: "trace" }
                | Error::CipherModulusMismatch { role: "trace" })
        ));
    }
    assert!(matches!(
        CbsParameters::try_new(
            &tfhe,
            ApproxSignedBasis::new(
                if modulus.explicit_value().is_some() {
                    None
                } else {
                    Some(132_120_577)
                },
                DecompositionBaseLog::new(8),
                Some(DecompositionLevelCount::new(2))
            ),
            trace.clone(),
            trace,
        ),
        Err(Error::OutputBasisModulusMismatch)
    ));
}

#[test]
fn circuit_parameters_check_capacity_ring_and_basis_domain() {
    check_circuit_parameters(
        BarrettModulus::new(1_125_899_906_826_241u64),
        Some(BarrettModulus::new(132_120_577)),
    );
    check_circuit_parameters(NativeModulus::<u64>::new(), None);

    // An explicit power-of-two Q is valid for ordinary parameter construction,
    // but CBS modular halving requires an odd modulus. Native remains supported.
    use primus_tfhe_ntru::{CbsGadgetConfig, CbsParameters, CircuitBootstrapParameterError};
    let tfhe = BlindRotationConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: NativeModulus::<u64>::new().into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: primus_modulus::PowOf2Modulus::new(1u64 << 16).into(),
        acc_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DECOMPOSITION,
            noise_standard_deviation: 0.7,
        },
        algorithm: BlindRotationAlgorithm::Classic,
    }
    .try_prepare()
    .and_then(|parameters| {
        parameters.try_with_key_switching(GadgetEncryptionConfig {
            decomposition: DECOMPOSITION,
            noise_standard_deviation: 0.7,
        })
    })
    .unwrap();
    let config = CbsGadgetConfig {
        output: DECOMPOSITION,
        trace: DECOMPOSITION,
        scheme_switch: DECOMPOSITION,
    };
    let trace = tfhe.blind_rotation();
    // Both derived and independently supplied components retain this check.
    for result in [
        CbsParameters::try_from_config(&tfhe, config),
        CbsParameters::try_new(&tfhe, trace.basis().clone(), trace.clone(), trace.clone()),
    ] {
        assert_eq!(
            result.err(),
            Some(CircuitBootstrapParameterError::UnsupportedTraceModulus)
        );
    }
}
