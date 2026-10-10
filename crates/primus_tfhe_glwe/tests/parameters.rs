//! GLWE-specific capacity, PBS order and independently paired CBS/KS domains.

use primus_glwe::GlweDimension;
use primus_lwe::LweDimension;
use primus_modulus::NativeModulus;
use primus_tfhe::{BlindRotationMethod, DecompositionBaseLog, DecompositionLevelCount, PolyLength};
use primus_tfhe_glwe::{
    CbsGadgetConfig, CbsParameters, DecompositionConfig, GadgetEncryptionConfig, LweConfig,
    ModulusConfig, PbsConfig, PbsMessageConfig, PbsOrder, PbsParameters, SecretKeyDistr,
    TfheParameterError,
};

fn decomposition(base: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(base),
        level_count: None,
    }
}

fn config(order: PbsOrder) -> PbsConfig<u32, NativeModulus<u32>> {
    PbsConfig {
        small_lwe: LweConfig {
            dimension: LweDimension::new(17),
            cipher_modulus: ModulusConfig::Native,
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 1.0,
        },
        bsk_dimension: GlweDimension::new(2),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(4),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(3),
            noise_standard_deviation: 3.2,
        },
        method: BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(8),
        order,
    }
}

fn gadget() -> CbsGadgetConfig {
    CbsGadgetConfig {
        trace: decomposition(4),
        scheme_switch: decomposition(4),
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
    }
}

#[test]
fn capacity_and_padded_return_follow_pbs_order() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        for n in [17, 33, 64] {
            let mut config = config(order);
            config.small_lwe.dimension = LweDimension::new(n);
            let parameters = PbsParameters::try_from_config(config).unwrap();
            let ks = parameters.glwe_key_switching();
            assert_eq!(ks.output_dimension().get(), n.div_ceil(32));
            assert_eq!(
                ks.output().secret_key_distr(),
                SecretKeyDistr::UniformBinary
            );
            assert_eq!(ks.output().noise_standard_deviation(), 3.2);
            assert_eq!(
                parameters
                    .blind_rotation_params()
                    .noise_standard_deviation(),
                0.7
            );
            assert_eq!(
                parameters.external_lwe_dimension().get(),
                if order == PbsOrder::BootstrapKeyswitch {
                    n
                } else {
                    64
                }
            );
        }
    }
    let mut too_large = config(PbsOrder::BootstrapKeyswitch);
    too_large.small_lwe.dimension = LweDimension::new(65);
    assert!(matches!(
        PbsParameters::try_from_config(too_large),
        Err(TfheParameterError::SmallLweDimensionExceedsGlweCapacity {
            small_lwe_dimension: 65,
            capacity: 64
        })
    ));
}

#[test]
fn cbs_pairing_tracks_input_encoding_and_only_input_ks() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let original = config(order);
        let cbs = CbsParameters::try_from_config(original, gadget()).unwrap();
        // Ordinary PBS output encoding is independent of the prepared CBS input.
        let mut changed = original;
        changed.messages.output_modulus = 16;
        assert!(
            cbs.clone()
                .try_with_pbs_parameters(PbsParameters::try_from_config(changed).unwrap())
                .is_ok()
        );
        changed.messages.input_modulus = 4;
        assert!(matches!(
            cbs.clone()
                .try_with_pbs_parameters(PbsParameters::try_from_config(changed).unwrap()),
            Err(TfheParameterError::IncompatibleComponents)
        ));

        // KS before BR changes CBS's input error; return-only KS may vary independently.
        changed = original;
        changed.key_switching.noise_standard_deviation = 2.0;
        changed.key_switching.decomposition = decomposition(2);
        let replacement = PbsParameters::try_from_config(changed).unwrap();
        let result = cbs.clone().try_with_pbs_parameters(replacement);
        match order {
            PbsOrder::BootstrapKeyswitch => assert!(result.is_ok()),
            PbsOrder::KeyswitchBootstrap => assert!(matches!(
                result,
                Err(TfheParameterError::IncompatibleComponents)
            )),
        }
        changed = original;
        changed.bsk_poly_length = PolyLength::new(64);
        assert!(matches!(
            cbs.try_with_pbs_parameters(PbsParameters::try_from_config(changed).unwrap()),
            Err(TfheParameterError::IncompatibleComponents)
        ));
    }
}
