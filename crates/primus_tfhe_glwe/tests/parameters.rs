use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe_glwe::{
    DecompositionConfig, GadgetEncryptionConfig, PbsOrder, TfheConfig, TfheParameters,
};
use std::error::Error;

const LWE_DIMENSION: usize = 8;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 32;
const PLAIN_MODULUS: u32 = 4;

type Components = (
    LweParameters<u32, NativeModulus<u32>>,
    GlweParameters<u32, NativeModulus<u32>>,
    ApproxSignedBasis<u32>,
);

fn components() -> Components {
    let small_lwe = LweParameters::new(
        LweDimension::new(LWE_DIMENSION),
        PLAIN_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glwe = GlweParameters::new(
        GlweDimension::new(GLWE_DIMENSION),
        PolyLength::new(POLY_LENGTH),
        PLAIN_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let bootstrapping = ApproxSignedBasis::new(
        glwe.cipher_modulus_value(),
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(3)),
    );
    (small_lwe, glwe, bootstrapping)
}

#[test]
fn derives_bootstrapping_and_key_switching_for_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let (small_lwe, glwe, bootstrapping) = components();
        let expected_blind_rotation_basis = bootstrapping.clone();
        let basis = ApproxSignedBasis::new(
            None,
            DecompositionBaseLog::new(4),
            Some(DecompositionLevelCount::new(4)),
        );
        let parameters = TfheParameters::try_from_config(TfheConfig {
            small_lwe: small_lwe.into_encryption_parameters(),
            accumulator_dimension: GlweDimension::new(GLWE_DIMENSION),
            poly_length: PolyLength::new(POLY_LENGTH),
            accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
            accumulator_noise_standard_deviation: 3.2,
            blind_rotation: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            key_switching: GadgetEncryptionConfig {
                decomposition: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(4),
                    level_count: Some(DecompositionLevelCount::new(4)),
                },
                noise_standard_deviation: 1.25,
            },
            pbs_order: order,
        })
        .unwrap();
        assert!(
            parameters.blind_rotation_ggsw().encryption_parameters()
                == glwe.encryption_parameters()
        );
        // Ordinary ring messages bind their own codec and retain the same sampler tables.
        let ordinary = GlweParameters::try_from_glev(
            parameters.blind_rotation_ggsw(),
            primus_encoding::ScaledCodec::new(3, NativeModulus::new()),
        )
        .unwrap();
        assert_eq!(ordinary.plain_modulus_value(), 3);
        assert!(std::ptr::eq(
            ordinary.encryption_parameters(),
            parameters.blind_rotation_ggsw().encryption_parameters()
        ));

        assert_eq!(
            parameters.blind_rotation_ggsw().basis(),
            &expected_blind_rotation_basis
        );

        assert_eq!(parameters.blind_rotation_ggsw().glwe_size(), glwe.size());
        assert_eq!(
            parameters
                .glwe_key_switching()
                .output()
                .noise_standard_deviation(),
            1.25
        );
        assert_eq!(
            parameters
                .small_lwe()
                .noise_distribution()
                .standard_deviation(),
            0.7
        );
        // Changing only KS noise through the direct constructor preserves the
        // BR and fresh LWE sampling domains, in either execution order.
        let changed = TfheParameters::try_new(
            parameters.small_lwe().clone(),
            parameters.blind_rotation_ggsw().clone(),
            GadgetEncryptionConfig {
                decomposition: basis.clone(),
                noise_standard_deviation: 2.5,
            },
            order,
        )
        .unwrap();
        assert_eq!(
            changed
                .small_lwe()
                .noise_distribution()
                .standard_deviation(),
            0.7
        );
        assert!(
            changed.blind_rotation_ggsw().encryption_parameters()
                == parameters.blind_rotation_ggsw().encryption_parameters()
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
            parameters.external_lwe_dimension(),
            LweDimension::new(match order {
                PbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
                PbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
            })
        );
    }
}

#[test]
fn rejects_key_switching_basis_from_another_modulus() {
    use primus_glwe::{GgswParameters, GlevParameterError::BasisModulusMismatch};
    use primus_tfhe_glwe::TfheParameterError;
    let (small_lwe, glwe, basis) = components();
    let result = TfheParameters::try_new(
        small_lwe.into_encryption_parameters(),
        GgswParameters::try_with_basis(&glwe, basis).unwrap(),
        GadgetEncryptionConfig {
            decomposition: ApproxSignedBasis::new(
                Some(257),
                DecompositionBaseLog::new(4),
                Some(DecompositionLevelCount::new(2)),
            ),
            noise_standard_deviation: glwe.noise_distribution().standard_deviation(),
        },
        PbsOrder::BootstrapKeyswitch,
    );
    let error = result.err().unwrap();
    assert_eq!(
        error,
        TfheParameterError::KeySwitchingParameters(BasisModulusMismatch)
    );
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<primus_glwe::GlevParameterError>(),
        Some(&BasisModulusMismatch)
    );
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
        let small_lwe = LweParameters::new(
            LweDimension::new(1),
            2,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let glwe = GlweParameters::new(
            GlweDimension::new(1),
            PolyLength::new(1 << log_n),
            2,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let basis = ApproxSignedBasis::new(None, DecompositionBaseLog::new(4), None);
        assert_eq!(
            TfheParameters::try_new(
                small_lwe.into_encryption_parameters(),
                primus_glwe::GgswParameters::try_with_basis(&glwe, basis.clone()).unwrap(),
                GadgetEncryptionConfig {
                    decomposition: basis,
                    noise_standard_deviation: glwe.noise_distribution().standard_deviation(),
                },
                PbsOrder::BootstrapKeyswitch
            )
            .err(),
            expected,
        );
    }
}

fn check_ternary_padding<M: primus_reduce::RingContext<u32>>(modulus: M) {
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
    let basis =
        ApproxSignedBasis::new(modulus.explicit_value(), DecompositionBaseLog::new(2), None);
    for distribution in [
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::ternary(0.2, 0.5),
        SecretKeyDistr::fixed_hamming_weight_ternary(33, 4),
        SecretKeyDistr::fixed_composition_ternary(33, 2, 2),
        SecretKeyDistr::gaussian(0.7),
    ] {
        let result = TfheParameters::try_new(
            (LweParameters::new(LweDimension::new(33), 2, modulus, distribution, 0.7))
                .into_encryption_parameters(),
            primus_glwe::GgswParameters::try_with_basis(&glwe, basis.clone()).unwrap(),
            GadgetEncryptionConfig {
                decomposition: basis.clone(),
                noise_standard_deviation: glwe.noise_distribution().standard_deviation(),
            },
            PbsOrder::BootstrapKeyswitch,
        );
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
            parameters.pbs_order(),
        );
        client.check_compatible(&parameters).unwrap();
        let padded = client.padded_small_glwe_secret_key(&parameters);
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

fn check_circuit_parameters<M: primus_reduce::RingContext<u64>>(modulus: M, foreign_modulus: M) {
    use primus_glwe::GgswParameters;
    use primus_tfhe_glwe::{
        CircuitBootstrapConfig, CircuitBootstrapParameterError as Error, CircuitBootstrapParameters,
    };

    let glwe = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(32),
        32,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let basis =
        ApproxSignedBasis::new(modulus.explicit_value(), DecompositionBaseLog::new(8), None);
    let tfhe = TfheParameters::try_new(
        (LweParameters::new(
            LweDimension::new(4),
            32,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        ))
        .into_encryption_parameters(),
        primus_glwe::GgswParameters::try_with_basis(&glwe, basis.clone()).unwrap(),
        GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: glwe.noise_distribution().standard_deviation(),
        },
        PbsOrder::BootstrapKeyswitch,
    )
    .unwrap();
    let config = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(2)),
        },
        trace: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(9),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 1.25,
        },
        scheme_switch: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: Some(DecompositionLevelCount::new(4)),
            },
            noise_standard_deviation: 2.5,
        },
    };
    let configured = CircuitBootstrapParameters::try_from_config(&tfhe, config).unwrap();
    assert_eq!(configured.output_size().glwe_size(), glwe.size());
    assert_eq!(configured.trace().basis().log_basis().get(), 9);
    assert_eq!(configured.trace().basis().decompose_length().get(), 3);
    assert_eq!(configured.trace().noise_standard_deviation(), 1.25);
    assert_eq!(configured.scheme_switch().basis().log_basis().get(), 10);
    assert_eq!(
        configured.scheme_switch().basis().decompose_length().get(),
        4
    );
    assert_eq!(configured.scheme_switch().noise_standard_deviation(), 2.5);
    for role in ["output", "trace", "scheme-switch"] {
        let mut invalid = config;
        match role {
            "output" => invalid.output.level_count = Some(DecompositionLevelCount::new(usize::MAX)),
            "trace" => {
                invalid.trace.decomposition.level_count =
                    Some(DecompositionLevelCount::new(usize::MAX))
            }
            _ => {
                invalid.scheme_switch.decomposition.level_count =
                    Some(DecompositionLevelCount::new(usize::MAX))
            }
        }
        let error = CircuitBootstrapParameters::try_from_config(&tfhe, invalid)
            .err()
            .unwrap();
        match role {
            "output" => assert!(matches!(error, Error::InvalidOutputBasis(_))),
            _ => assert!(
                matches!(error, Error::GadgetParameters { role: actual, .. } if actual == role)
            ),
        }
    }
    let trace = tfhe.blind_rotation_ggsw();
    let output = |levels| {
        ApproxSignedBasis::new(
            modulus.explicit_value(),
            DecompositionBaseLog::new(8),
            Some(DecompositionLevelCount::new(levels)),
        )
    };
    assert!(
        CircuitBootstrapParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone()).is_ok()
    );
    // Key geometry can be valid even when one message program does not fit.
    // Two lanes fit t=32 at N=32; three levels pad to four lanes and do not.
    let two = CircuitBootstrapParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone())
        .unwrap();
    let three = CircuitBootstrapParameters::try_new(&tfhe, output(3), trace.clone(), trace.clone())
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
            CircuitBootstrapParameters::try_new(
                &tfhe,
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
                CircuitBootstrapParameters::try_new(&tfhe, output(2), trace, scheme_switch).err(),
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
    use primus_tfhe_glwe::{
        CircuitBootstrapConfig, CircuitBootstrapParameterError, CircuitBootstrapParameters,
        TfheParameterError,
    };
    let basis = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: Some(DecompositionLevelCount::new(2)),
    };
    let config = TfheConfig {
        small_lwe: primus_lwe::LweEncryptionParameters::new(
            LweDimension::new(4),
            NativeModulus::<u32>::new(),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: PolyLength::new(32),
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: basis,
        key_switching: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        pbs_order: PbsOrder::BootstrapKeyswitch,
    };
    let tfhe = TfheParameters::try_from_config(config.clone()).unwrap();
    // Both TFHE constructors reject invalid independent KS noise at setup.
    for sigma in [0.0, -1.0, f64::NAN, f64::INFINITY, f64::MAX] {
        let mut invalid = config.clone();
        invalid.key_switching.noise_standard_deviation = sigma;
        for result in [
            TfheParameters::try_from_config(invalid),
            TfheParameters::try_new(
                tfhe.small_lwe().clone(),
                tfhe.blind_rotation_ggsw().clone(),
                GadgetEncryptionConfig {
                    decomposition: tfhe.glwe_key_switching().output().basis().clone(),
                    noise_standard_deviation: sigma,
                },
                tfhe.pbs_order(),
            ),
        ] {
            assert!(matches!(
                result,
                Err(TfheParameterError::KeySwitchingEncryption(
                    GlweParameterError::Noise(_)
                ))
            ));
        }
    }
    let mut invalid = config.clone();
    invalid.accumulator_noise_standard_deviation = f64::NAN;
    assert!(matches!(
        TfheParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            GlweParameterError::Noise(_)
        ))
    ));
    let mut invalid = config;
    invalid.accumulator_secret_key_distr = SecretKeyDistr::Ternary {
        negative_one_probability: 0.8,
        one_probability: 0.8,
    };
    assert!(matches!(
        TfheParameters::try_from_config(invalid),
        Err(TfheParameterError::AccumulatorParameters(
            GlweParameterError::SecretKey(_)
        ))
    ));

    let cbs = CircuitBootstrapConfig {
        output: basis,
        trace: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
        scheme_switch: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 0.7,
        },
    };
    assert!(CircuitBootstrapParameters::try_from_config(&tfhe, cbs).is_ok());
    for role in ["trace", "scheme-switch"] {
        let mut invalid = cbs;
        if role == "trace" {
            invalid.trace.noise_standard_deviation = 0.0;
        } else {
            invalid.scheme_switch.noise_standard_deviation = f64::INFINITY;
        }
        let error = CircuitBootstrapParameters::try_from_config(&tfhe, invalid)
            .err()
            .unwrap();
        assert!(matches!(
            &error,
            CircuitBootstrapParameterError::EncryptionParameters { role: actual, source: GlweParameterError::Noise(_) } if *actual == role
        ));
        // Follow a real constructor failure through the public key-generation
        // wrapper. Each frame keeps its role and prints only its own context.
        use std::error::Error;
        let error = primus_tfhe_glwe::KeyGenerationError::from(error);
        assert_eq!(
            error.to_string(),
            format!("invalid circuit-bootstrap {role} encryption parameters")
        );
        let parameters = error.source().unwrap();
        assert!(parameters.is::<GlweParameterError>());
        assert_eq!(parameters.to_string(), "invalid GLWE noise distribution");
        let sampler = parameters.source().unwrap();
        assert!(matches!(
            sampler.downcast_ref::<primus_distr::GaussianError>(),
            Some(primus_distr::GaussianError::InvalidStandardDeviation { .. })
        ));
        assert!(sampler.source().is_none());
    }
}
