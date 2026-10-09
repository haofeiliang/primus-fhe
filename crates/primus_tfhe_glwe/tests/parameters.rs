use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lattice::{GlweDimension, LweDimension};
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationMethod;
use primus_tfhe_glwe::{DecompositionConfig, GadgetEncryptionConfig, PbsOrder, PbsParameters};
use primus_tfhe_glwe::{LweConfig, PbsConfig, PbsMessageConfig};

const LWE_DIMENSION: usize = 8;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 32;
const PLAIN_MODULUS: u32 = 4;

fn config() -> PbsConfig<u32, NativeModulus<u32>> {
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(LWE_DIMENSION),
            cipher_modulus: primus_tfhe::ModulusConfig::Native,
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(GLWE_DIMENSION),
        bsk_poly_length: PolyLength::new(POLY_LENGTH),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 3.2,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(2),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        order: PbsOrder::BootstrapKeyswitch,
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(PLAIN_MODULUS),
    }
}

#[test]
fn derives_bootstrapping_and_key_switching_for_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let glwe = GlweParameters::new(
            GlweDimension::new(GLWE_DIMENSION),
            PolyLength::new(POLY_LENGTH),
            PLAIN_MODULUS,
            NativeModulus::new(),
            SecretKeyDistr::SparseTernary,
            3.2,
        );
        let expected_blind_rotation_basis = ApproxSignedBasis::new(
            None,
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(3)),
        );
        let basis = ApproxSignedBasis::new(
            None,
            DecompositionBaseLog::new(4),
            Some(DecompositionLevelCount::new(4)),
        );
        let key_switching = GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(4)),
            },
            noise_standard_deviation: 1.25,
        };
        let config = PbsConfig {
            key_switching,
            order,
            ..config()
        };
        let parameters = PbsParameters::try_from_config(config).unwrap();
        assert!(
            parameters
                .as_ref()
                .blind_rotation_params()
                .encryption_parameters()
                == glwe.encryption_parameters()
        );
        // Ordinary ring messages bind their own codec and retain the same sampler tables.
        let ordinary = GlweParameters::try_from_glev(
            parameters.as_ref().blind_rotation_params(),
            primus_encoding::ScaledCodec::new(3, NativeModulus::new()),
        )
        .unwrap();
        assert_eq!(ordinary.plain_modulus_value(), 3);
        assert!(std::ptr::eq(
            ordinary.encryption_parameters(),
            parameters
                .as_ref()
                .blind_rotation_params()
                .encryption_parameters()
        ));

        assert_eq!(
            parameters.as_ref().blind_rotation_params().basis(),
            &expected_blind_rotation_basis
        );

        assert_eq!(
            parameters.as_ref().blind_rotation_params().glwe_size(),
            glwe.size()
        );
        assert_eq!(
            parameters
                .glwe_key_switching()
                .output()
                .noise_standard_deviation(),
            1.25
        );
        assert_eq!(
            parameters
                .as_ref()
                .small_lwe()
                .noise_distribution()
                .standard_deviation(),
            0.7
        );
        // Changing only KS noise in the config preserves the
        // BR and fresh LWE sampling domains, in either execution order.
        let changed = PbsParameters::try_from_config(PbsConfig {
            key_switching: GadgetEncryptionConfig {
                noise_standard_deviation: 2.5,
                ..key_switching
            },
            ..config
        })
        .unwrap();
        assert_eq!(
            changed
                .as_ref()
                .small_lwe()
                .noise_distribution()
                .standard_deviation(),
            0.7
        );
        assert!(
            changed
                .as_ref()
                .blind_rotation_params()
                .encryption_parameters()
                == parameters
                    .as_ref()
                    .blind_rotation_params()
                    .encryption_parameters()
        );
        assert_eq!(
            changed
                .glwe_key_switching()
                .output()
                .noise_standard_deviation(),
            2.5
        );
        assert_eq!(
            parameters.glwe_key_switching().input_dimension(),
            GlweDimension::new(GLWE_DIMENSION)
        );
        assert_eq!(
            parameters.glwe_key_switching().output_dimension(),
            GlweDimension::new(1)
        );
        assert_eq!(
            parameters.glwe_key_switching().poly_length(),
            PolyLength::new(POLY_LENGTH)
        );
        assert_eq!(
            parameters.glwe_key_switching().output().secret_key_distr(),
            SecretKeyDistr::UniformBinary
        );
        assert_eq!(parameters.glwe_key_switching().output().basis(), &basis);
        assert_eq!(
            parameters.as_ref().external_lwe_dimension(),
            LweDimension::new(match order {
                PbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
                PbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
            })
        );
    }
}

#[test]
fn rotation_domain_must_be_representable_by_input_coefficients() {
    use primus_tfhe_glwe::TfheParameterError;

    let modulus = NativeModulus::<u16>::new();
    for (log_n, expected) in [
        (14, None),
        (15, Some(TfheParameterError::RotationDomainTooLarge)),
        (16, Some(TfheParameterError::RotationDomainTooLarge)),
    ] {
        assert_eq!(
            PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
                small_lwe: primus_tfhe::LweConfig {
                    dimension: LweDimension::new(1),
                    cipher_modulus: modulus.into(),
                    secret_key_distr: SecretKeyDistr::UniformBinary,
                    noise_standard_deviation: 0.7
                },
                bsk_dimension: GlweDimension::new(1),
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
                    decomposition: primus_tfhe::DecompositionConfig {
                        log_basis: DecompositionBaseLog::new(4),
                        level_count: None
                    },
                    noise_standard_deviation: 0.7,
                },
                method: primus_tfhe::BlindRotationMethod::Classic,
                messages: primus_tfhe::PbsMessageConfig::new(4),
                order: PbsOrder::BootstrapKeyswitch
            })
            .err(),
            expected,
        );
    }
}

fn check_ternary_padding<
    M: primus_reduce::RingContext<u32>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
>(
    modulus: M,
) {
    use primus_glwe::GlweSecretKey;
    use primus_lwe::LweSecretKey;
    use primus_tfhe_glwe::{ClientKey, TfheParameterError};

    // A 33-dimensional LWE secret crosses two length-32 GLWE components.
    let glwe = GlweParameters::new(
        GlweDimension::new(2),
        PolyLength::new(32),
        2,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    for distribution in [
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::ternary(0.2, 0.5),
        SecretKeyDistr::fixed_hamming_weight_ternary(33, 4),
        SecretKeyDistr::fixed_composition_ternary(33, 2, 2),
        SecretKeyDistr::gaussian(0.7),
    ] {
        let result = PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
            small_lwe: primus_tfhe::LweConfig {
                dimension: LweDimension::new(33),
                cipher_modulus: modulus.into(),
                secret_key_distr: distribution,
                noise_standard_deviation: 0.7,
            },
            bsk_dimension: GlweDimension::new(2),
            bsk_poly_length: PolyLength::new(32),
            bsk_secret_distr: SecretKeyDistr::UniformBinary,
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: primus_tfhe::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(2),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            key_switching: GadgetEncryptionConfig {
                decomposition: primus_tfhe::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(2),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            method: primus_tfhe::BlindRotationMethod::Classic,
            messages: primus_tfhe::PbsMessageConfig::new(4),
            order: PbsOrder::BootstrapKeyswitch,
        });
        if !distribution.is_ternary() {
            assert_eq!(
                result.err(),
                Some(TfheParameterError::UnsupportedInputLweSecretKey)
            );
            continue;
        }
        let parameters = result.unwrap();
        let mut coefficients = vec![0; 33];
        coefficients[..4].copy_from_slice(&[0, 1, modulus.minus_one(), modulus.minus_one()]);
        coefficients[32] = 1;
        let client = ClientKey::new(
            LweSecretKey::new(coefficients, distribution, modulus),
            GlweSecretKey::<u32>::new(
                vec![0; glwe.size().mask_len()],
                glwe.size(),
                glwe.secret_key_distr(),
            ),
            parameters.as_ref().pbs_order(),
        );
        client.check_compatible(parameters.as_ref()).unwrap();
        let padded = client.padded_small_glwe_secret_key(parameters.as_ref());
        let mut expected = vec![0; glwe.size().mask_len()];
        expected[..4].copy_from_slice(&[0, 1, -1, -1]);
        expected[32] = 1;
        assert_eq!(padded.as_slice(), expected);
        assert_eq!(padded.distr(), distribution);
    }
}

#[test]
fn ternary_parameters_and_padded_keys_preserve_signed_coefficients() {
    check_ternary_padding(NativeModulus::new());
    check_ternary_padding(primus_modulus::BarrettModulus::new(257));
    check_ternary_padding(primus_modulus::PowOf2Modulus::new(256));
}

fn check_circuit_parameters<
    M: primus_reduce::RingContext<u64>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
>(
    modulus: M,
    foreign_modulus: M,
) {
    use primus_glwe::GgswParameters;
    use primus_tfhe_glwe::{
        CbsGadgetConfig, CbsGadgetParameters, CircuitBootstrapParameterError as Error,
    };

    let glwe = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(32),
        32,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let tfhe = PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: modulus.into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(4),
        order: PbsOrder::BootstrapKeyswitch,
    })
    .unwrap();
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
    assert_eq!(configured.output_size().glwe_size(), glwe.size());
    assert_eq!(configured.output_basis().log_basis().get(), 8);
    assert_eq!(
        configured.output_size().glev_len(),
        glwe.size().glwe_len() * 2
    );
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
            tfhe.as_ref()
                .blind_rotation_params()
                .encryption_parameters(),
        ));
        assert_eq!(parameters.noise_standard_deviation(), 0.7);
    }
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
    let trace = tfhe.as_ref().blind_rotation_params();
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
    // Key geometry can be valid even when one message program does not fit.
    // Two lanes fit t=32 at N=32; three levels pad to four lanes and do not.
    let two = CbsGadgetParameters::try_new(tfhe.as_ref(), output(2), trace.clone(), trace.clone())
        .unwrap();
    let three =
        CbsGadgetParameters::try_new(tfhe.as_ref(), output(3), trace.clone(), trace.clone())
            .unwrap();
    let codec = primus_encoding::RoundedCodec::new(32, modulus);
    assert!(two.compile_lookup_table(&codec).is_ok());
    assert!(matches!(
        three.compile_lookup_table(&codec),
        Err(primus_tfhe::LookupTableError::PlaintextDomainTooLarge { .. })
    ));
    assert!(
        three
            .compile_lookup_table(&primus_encoding::RoundedCodec::new(8, modulus))
            .is_ok()
    );
    if foreign_modulus != modulus {
        assert_eq!(
            three
                .compile_lookup_table(&primus_encoding::RoundedCodec::new(8, foreign_modulus))
                .err(),
            Some(primus_tfhe::LookupTableError::InputModulusMismatch)
        );
    }
    // Distinguish a different explicit modulus from Native/explicit representation mismatch.
    for other in [
        Some(132_120_577),
        if modulus.explicit_value().is_some() {
            None
        } else {
            Some(1 << 63)
        },
    ] {
        assert_eq!(
            CbsGadgetParameters::try_new(
                tfhe.as_ref(),
                ApproxSignedBasis::new(
                    other,
                    DecompositionBaseLog::new(8),
                    Some(DecompositionLevelCount::new(2))
                ),
                trace.clone(),
                trace.clone()
            )
            .err(),
            Some(Error::OutputBasisModulusMismatch),
        );
    }
    for (dimension, n, q) in [(2, 32, modulus), (1, 64, modulus), (1, 32, foreign_modulus)] {
        if dimension == 1 && n == 32 && q == modulus {
            continue;
        }
        let foreign = GgswParameters::with_glwe_params(
            &GlweParameters::new(
                GlweDimension::new(dimension),
                PolyLength::new(n),
                32,
                q,
                SecretKeyDistr::UniformBinary,
                0.7,
            ),
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(2)),
        );
        for (role, trace, scheme_switch) in [
            ("trace", foreign.clone(), trace.clone()),
            ("scheme-switch", trace.clone(), foreign.clone()),
        ] {
            let expected = if dimension != 1 || n != 32 {
                Error::GlweLayoutMismatch { role }
            } else {
                Error::CipherModulusMismatch { role }
            };
            assert_eq!(
                CbsGadgetParameters::try_new(tfhe.as_ref(), output(2), trace, scheme_switch).err(),
                Some(expected)
            );
        }
    }
}

#[test]
fn circuit_parameters_bind_bases_layout_noise_and_capacity() {
    check_circuit_parameters(NativeModulus::new(), NativeModulus::new());
    check_circuit_parameters(
        primus_modulus::BarrettModulus::new(1_125_899_906_826_241),
        primus_modulus::BarrettModulus::new(562_949_953_392_641),
    );
}

#[test]
fn configs_return_role_specific_sampling_errors() {
    use primus_glwe::GlweParameterError;
    use primus_tfhe_glwe::TfheParameterError;
    let basis = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: Some(DecompositionLevelCount::new(2)),
    };
    let config = PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: NativeModulus::<u32>::new().into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        method: BlindRotationMethod::Classic,
        key_switching: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        messages: PbsMessageConfig::new(4),
        order: PbsOrder::BootstrapKeyswitch,
    };
    let tfhe = PbsParameters::try_from_config(config).unwrap();
    // Both TFHE constructors reject invalid independent KS noise at setup.
    for sigma in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::MAX] {
        let mut invalid = config;
        invalid.key_switching.noise_standard_deviation = sigma;
        for result in [
            PbsParameters::try_from_config(invalid),
            PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
                small_lwe: primus_tfhe::LweConfig {
                    dimension: (tfhe.as_ref().small_lwe()).dimension(),
                    cipher_modulus: (tfhe.as_ref().small_lwe()).cipher_modulus().into(),
                    secret_key_distr: (tfhe.as_ref().small_lwe()).secret_key_distr(),
                    noise_standard_deviation: (tfhe.as_ref().small_lwe())
                        .noise_standard_deviation(),
                },
                bsk_dimension: (tfhe.as_ref().blind_rotation_params()).dimension(),
                bsk_poly_length: (tfhe.as_ref().blind_rotation_params()).poly_length(),
                bsk_secret_distr: (tfhe.as_ref().blind_rotation_params())
                    .encryption_parameters()
                    .secret_key_distr(),
                bsk_gadget: GadgetEncryptionConfig {
                    decomposition: primus_tfhe::DecompositionConfig {
                        log_basis: ((tfhe.as_ref().blind_rotation_params()).basis()).log_basis(),
                        level_count: Some(
                            ((tfhe.as_ref().blind_rotation_params()).basis()).decompose_length(),
                        ),
                    },
                    noise_standard_deviation: (tfhe.as_ref().blind_rotation_params())
                        .encryption_parameters()
                        .noise_distribution()
                        .standard_deviation(),
                },
                key_switching: GadgetEncryptionConfig {
                    decomposition: primus_tfhe::DecompositionConfig {
                        log_basis: (tfhe.glwe_key_switching().output().basis().clone()).log_basis(),
                        level_count: Some(
                            (tfhe.glwe_key_switching().output().basis().clone()).decompose_length(),
                        ),
                    },
                    noise_standard_deviation: sigma,
                },
                method: primus_tfhe::BlindRotationMethod::Classic,
                messages: primus_tfhe::PbsMessageConfig::new(4),
                order: tfhe.as_ref().pbs_order(),
            }),
        ] {
            assert!(matches!(
                result,
                Err(TfheParameterError::KeySwitchingEncryption(
                    GlweParameterError::Noise(_)
                ))
            ));
        }
    }
    let mut invalid = config;
    invalid.bsk_gadget.noise_standard_deviation = f64::NAN;
    assert!(matches!(
        PbsParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            GlweParameterError::Noise(_)
        ))
    ));
    let mut invalid = config;
    invalid.bsk_secret_distr = SecretKeyDistr::Ternary {
        negative_one_probability: 0.8,
        one_probability: 0.8,
    };
    assert!(matches!(
        PbsParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            GlweParameterError::SecretKey(_)
        ))
    ));
}

/// Complete CBS reuses BR sampling state and retains KS for the selected input path.
#[test]
fn complete_cbs_reuses_br_and_checks_input_stage() {
    use primus_tfhe_glwe::{CbsGadgetConfig, CbsParameters, PbsParameters};

    let br = PbsParameters::try_from_config(config()).unwrap();
    let decomposition = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: Some(DecompositionLevelCount::new(2)),
    };
    let gadget = CbsGadgetConfig {
        output: decomposition,
        trace: decomposition,
        scheme_switch: decomposition,
    };
    let ks = GadgetEncryptionConfig {
        decomposition,
        noise_standard_deviation: 1.25,
    };
    let direct = CbsParameters::try_with_config(br.clone(), gadget).unwrap();
    assert!(br.has_same_domain(direct.pbs_parameters()));
    assert!(std::ptr::eq(
        br.blind_rotation_params().encryption_parameters(),
        direct.gadget().trace().encryption_parameters()
    ));
    assert!(direct.pbs_parameters().input_key_switching().is_none());
    let switched = CbsParameters::try_from_config(
        PbsConfig {
            key_switching: ks,
            order: PbsOrder::KeyswitchBootstrap,
            ..config()
        },
        gadget,
    )
    .unwrap();
    assert_eq!(
        switched
            .pbs_parameters()
            .input_key_switching()
            .unwrap()
            .output()
            .noise_standard_deviation(),
        1.25
    );
    assert!(!br.has_same_domain(switched.as_ref()));

    assert!(
        CbsParameters::try_with_config(
            br.clone()
                .with_messages(primus_tfhe::PbsMessageConfig::new(1)),
            gadget
        )
        .is_err()
    );
    // An equal numerical domain remains reusable even when independently prepared.
    let equal = PbsParameters::try_from_config(PbsConfig {
        method: BlindRotationMethod::Sparse {
            copy_count: 3,
            bucket_count: 4,
        },
        ..config()
    })
    .unwrap();
    assert!(br.has_same_domain(&equal));
}
