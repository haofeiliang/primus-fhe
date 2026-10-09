use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationMethod;
use primus_tfhe_ntru::{
    DecompositionConfig, GadgetEncryptionConfig, PbsParameters, TfheParameterError,
};
use primus_tfhe_ntru::{LweConfig, PbsConfig, PbsMessageConfig};
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
        external_lwe: LweConfig {
            dimension: LweDimension::new(N * 2),
            cipher_modulus: BarrettModulus::new(65_537).into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: BarrettModulus::new(Q).into(),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(9),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 1.25,
        },
        algorithm: BlindRotationMethod::Classic,
        key_switching: GadgetEncryptionConfig {
            decomposition: DECOMPOSITION,
            noise_standard_deviation: 2.5,
        },
        messages: PbsMessageConfig::new(4),
    };
    let parameters = PbsParameters::try_from_config(config).unwrap();
    // Binding ordinary ring messages reuses the gadget's sampler allocation.
    let ordinary = NtruParameters::try_from_nlev(
        parameters.as_ref().blind_rotation(),
        primus_encoding::ScaledCodec::new(
            4,
            parameters.as_ref().accumulator_ntru().cipher_modulus(),
        ),
    )
    .unwrap();
    assert!(std::ptr::eq(
        ordinary.encryption_parameters(),
        parameters.as_ref().accumulator_ntru()
    ));
    assert_eq!(parameters.as_ref().poly_length(), PolyLength::new(N));
    assert_eq!(
        parameters.as_ref().external_lwe_dimension(),
        LweDimension::new(N * 2)
    );
    assert_eq!(
        parameters
            .as_ref()
            .accumulator_ntru()
            .cipher_modulus_value(),
        Some(Q)
    );
    assert_eq!(
        parameters.as_ref().external_lwe().cipher_modulus_value(),
        Some(65_537)
    );
    assert_eq!(parameters.key_switching().basis().modulus(), Some(65_537));
    assert_eq!(
        parameters.as_ref().accumulator_ntru().secret_key_distr(),
        SecretKeyDistr::SparseTernary
    );
    assert_eq!(
        parameters.key_switching().lwe().secret_key_distr(),
        SecretKeyDistr::UniformBinary
    );
    assert_eq!(
        parameters
            .as_ref()
            .external_lwe()
            .noise_standard_deviation(),
        0.7
    );
    assert_eq!(
        parameters
            .as_ref()
            .accumulator_ntru()
            .noise_distribution()
            .standard_deviation(),
        1.25
    );
    assert_eq!(
        parameters.key_switching().lwe().noise_standard_deviation(),
        2.5
    );
    for blind_rotation in [true, false] {
        let mut invalid = config;
        let decomposition = if blind_rotation {
            &mut invalid.bsk_gadget.decomposition
        } else {
            &mut invalid.key_switching.decomposition
        };
        decomposition.level_count = Some(DecompositionLevelCount::new(usize::MAX));
        let error = PbsParameters::try_from_config(invalid).err().unwrap();
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
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::ternary(0.2, 0.3),
        SecretKeyDistr::fixed_hamming_weight_ternary(N, 7),
        SecretKeyDistr::fixed_composition_ternary(N, 3, 4),
        SecretKeyDistr::gaussian(3.2),
    ] {
        let result = PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
            external_lwe: primus_tfhe::LweConfig {
                dimension: LweDimension::new(N),
                cipher_modulus: (BarrettModulus::new(65_537)).into(),
                secret_key_distr: distr,
                noise_standard_deviation: 0.7,
            },
            acc_modulus: modulus.into(),
            bsk_poly_length: PolyLength::new(N),
            bsk_secret_distr: SecretKeyDistr::SparseTernary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: primus_tfhe::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(9),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            key_switching: GadgetEncryptionConfig {
                decomposition: DECOMPOSITION,
                noise_standard_deviation: 0.7,
            },
            algorithm: primus_tfhe::BlindRotationMethod::Classic,
            messages: primus_tfhe::PbsMessageConfig::new(4),
        });
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
        assert_eq!(
            PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
                external_lwe: primus_tfhe::LweConfig {
                    dimension: LweDimension::new(1),
                    cipher_modulus: modulus.into(),
                    secret_key_distr: SecretKeyDistr::UniformBinary,
                    noise_standard_deviation: 0.7
                },
                acc_modulus: modulus.into(),
                bsk_poly_length: PolyLength::new(1 << log_n),
                bsk_secret_distr: SecretKeyDistr::UniformBinary,
                bsk_gadget: GadgetEncryptionConfig {
                    decomposition: primus_tfhe::DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(4),
                        level_count: None
                    },
                    noise_standard_deviation: 0.7
                },
                key_switching: GadgetEncryptionConfig {
                    decomposition: DECOMPOSITION,
                    noise_standard_deviation: 0.7,
                },
                algorithm: primus_tfhe::BlindRotationMethod::Classic,
                messages: primus_tfhe::PbsMessageConfig::new(4)
            })
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
        external_lwe: LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: primus_modulus::PowOf2Modulus::new(256u32).into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: BarrettModulus::new(257).into(),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        algorithm: BlindRotationMethod::Classic,
        key_switching: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        messages: PbsMessageConfig::new(4),
    };
    let mut invalid = config;
    invalid.bsk_gadget.noise_standard_deviation = f64::NAN;
    assert!(matches!(
        PbsParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::Noise(_)
        ))
    ));
    let mut invalid = config;
    invalid.bsk_secret_distr = SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 33 };
    assert!(matches!(
        PbsParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            NtruParameterError::SecretKey(_)
        ))
    ));
    let mut invalid = config;
    invalid.key_switching.noise_standard_deviation = 0.0;
    assert!(matches!(
        PbsParameters::try_from_config(invalid),
        Err(TfheParameterError::KeySwitchingEncryption(
            primus_lwe::LweParameterError::Noise(_)
        ))
    ));
}

// These constructors do not depend on a transform table or encrypted keys.
fn check_circuit_parameters<
    M: primus_reduce::RingContext<u64>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
>(
    modulus: M,
    foreign_modulus: Option<M>,
) {
    use primus_tfhe_ntru::{
        CbsGadgetConfig, CbsGadgetParameters, CircuitBootstrapParameterError as Error,
    };
    let make = |plain| {
        PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
            external_lwe: primus_tfhe::LweConfig {
                dimension: LweDimension::new(16),
                cipher_modulus: modulus.into(),
                secret_key_distr: SecretKeyDistr::UniformBinary,
                noise_standard_deviation: 0.7,
            },
            acc_modulus: modulus.into(),
            bsk_poly_length: PolyLength::new(N),
            bsk_secret_distr: SecretKeyDistr::SparseTernary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: primus_tfhe::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(10),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            key_switching: GadgetEncryptionConfig {
                decomposition: primus_tfhe_ntru::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(10),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            algorithm: primus_tfhe::BlindRotationMethod::Classic,
            messages: primus_tfhe::PbsMessageConfig::new(plain),
        })
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
    let configured = CbsGadgetParameters::try_from_config(tfhe.as_ref(), config).unwrap();
    assert_eq!(configured.poly_length(), tfhe.as_ref().poly_length());
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
            tfhe.as_ref().accumulator_ntru(),
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
        let error = CbsGadgetParameters::try_from_config(tfhe.as_ref(), invalid)
            .err()
            .unwrap();
        match role {
            "output" => assert!(matches!(error, Error::InvalidOutputBasis(_))),
            _ => assert!(
                matches!(error, Error::GadgetParameters { role: actual, .. } if actual == role)
            ),
        }
    }
    let trace = tfhe.as_ref().blind_rotation().clone();
    let output = |levels| {
        ApproxSignedBasis::new(
            modulus.explicit_value(),
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(levels)),
        )
    };
    assert!(
        CbsGadgetParameters::try_new(tfhe.as_ref(), output(2), trace.clone(), trace.clone())
            .is_ok()
    );
    // Capacity depends on the input encoding, so reject when compiling the
    // CBS program; the same key parameters accept a smaller plaintext domain.
    let cbs = CbsGadgetParameters::try_new(tfhe.as_ref(), output(3), trace.clone(), trace.clone())
        .unwrap();
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
            CbsGadgetParameters::try_new(
                tfhe.as_ref(),
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
        CbsGadgetParameters::try_new(
            tfhe.as_ref(),
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
    use primus_tfhe_ntru::{CbsGadgetConfig, CbsGadgetParameters, CircuitBootstrapParameterError};
    let tfhe = PbsParameters::try_from_config(PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: NativeModulus::<u64>::new().into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: primus_modulus::PowOf2Modulus::new(1u64 << 16).into(),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DECOMPOSITION,
            noise_standard_deviation: 0.7,
        },
        algorithm: BlindRotationMethod::Classic,
        key_switching: GadgetEncryptionConfig {
            decomposition: DECOMPOSITION,
            noise_standard_deviation: 0.7,
        },
        messages: primus_tfhe::PbsMessageConfig::new(4),
    })
    .unwrap();
    let config = CbsGadgetConfig {
        output: DECOMPOSITION,
        trace: DECOMPOSITION,
        scheme_switch: DECOMPOSITION,
    };
    let trace = tfhe.as_ref().blind_rotation();
    // Both derived and independently supplied components retain this check.
    for result in [
        CbsGadgetParameters::try_from_config(tfhe.as_ref(), config),
        CbsGadgetParameters::try_new(
            tfhe.as_ref(),
            trace.basis().clone(),
            trace.clone(),
            trace.clone(),
        ),
    ] {
        assert_eq!(
            result.err(),
            Some(CircuitBootstrapParameterError::UnsupportedTraceModulus)
        );
    }
}

/// Complete CBS shares accumulator samplers and prepares selector encoding at external q.
#[test]
fn complete_cbs_reuses_br_and_keeps_selector_encoding_at_q() {
    use primus_tfhe_ntru::{CbsConfig, CbsGadgetConfig, CbsParameters};
    let config = CbsConfig {
        gadget: CbsGadgetConfig {
            output: DECOMPOSITION,
            trace: DECOMPOSITION,
            scheme_switch: DECOMPOSITION,
        },
        pbs: PbsConfig {
            external_lwe: LweConfig {
                dimension: LweDimension::new(4),
                cipher_modulus: BarrettModulus::new(65_537u32).into(),
                secret_key_distr: SecretKeyDistr::UniformBinary,
                noise_standard_deviation: 0.7,
            },
            acc_modulus: BarrettModulus::new(Q).into(),
            bsk_poly_length: PolyLength::new(N),
            bsk_secret_distr: SecretKeyDistr::SparseTernary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: DECOMPOSITION,
                noise_standard_deviation: 1.25,
            },
            algorithm: BlindRotationMethod::Classic,
            key_switching: GadgetEncryptionConfig {
                decomposition: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(2),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            messages: primus_tfhe::PbsMessageConfig::new(4),
        },
    };
    let br = PbsParameters::try_from_config(config.pbs).unwrap();
    let operation = CbsParameters::try_with_config(br.clone(), config.gadget).unwrap();
    assert!(br.has_same_domain(operation.pbs_parameters()));
    assert!(std::ptr::eq(
        br.accumulator_ntru(),
        operation.gadget().trace().encryption_parameters()
    ));
    assert_eq!(
        operation.input_codec().ciphertext_modulus(),
        br.external_lwe().cipher_modulus()
    );
    assert_eq!(operation.input_codec().plaintext_modulus(), 4);
    let equal = CbsParameters::try_from_config(config.pbs, config.gadget).unwrap();
    assert!(br.has_same_domain(equal.as_ref()));
    let mut foreign = config;
    foreign.pbs.external_lwe.dimension = LweDimension::new(5);
    let foreign_parameters = CbsParameters::try_from_config(foreign.pbs, foreign.gadget).unwrap();
    assert!(!br.has_same_domain(foreign_parameters.as_ref()));
    foreign = config;
    foreign.pbs.messages.input_modulus = 1;
    assert!(CbsParameters::try_from_config(foreign.pbs, foreign.gadget).is_err());
}
