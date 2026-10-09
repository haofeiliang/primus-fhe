use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{FftTable, RustFftTable};
use primus_lattice::LweDimension;
use primus_modulus::NativeModulus;
use primus_ntru::SecretKeyDistr;
use primus_poly::PolyLength;
use primus_tfhe_ntru_fourier::{
    GadgetEncryptionConfig, PbsParameters, TfheContext, TfheEvaluationError,
};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 32;
const LWE_DIMENSION: usize = 4;
const PLAIN_MODULUS: u32 = 4;

fn parameters(bootstrapping_log_basis: u32, key_switching_log_basis: u32) -> PbsParameters<u32> {
    let modulus = NativeModulus::new();

    PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
        external_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(LWE_DIMENSION),
            cipher_modulus: modulus.into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: modulus.into(),
        bsk_poly_length: PolyLength::new(POLY_LENGTH),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(bootstrapping_log_basis),
                level_count: Some(DecompositionLevelCount::new(4)),
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(key_switching_log_basis),
                level_count: Some(DecompositionLevelCount::new(4)),
            },
            noise_standard_deviation: 0.7,
        },
        algorithm: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(PLAIN_MODULUS),
    })
    .unwrap()
}

#[test]
fn rejects_server_keys_with_same_layout_but_different_bases() {
    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
    let context_parameters = &parameters(8, 8);
    let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();

    let mut rng = StdRng::seed_from_u64(0x464f_5552_4241_5349);
    let (_, server_key) = context.try_generate_keys(&mut rng).unwrap();

    assert!(context.evaluator(&server_key).is_ok());

    // Changing either basis preserves all four levels and their storage size.
    for (bootstrapping_log_basis, key_switching_log_basis) in [(7, 8), (8, 7)] {
        let candidate = parameters(bootstrapping_log_basis, key_switching_log_basis);
        assert_eq!(
            candidate.as_ref().blind_rotation().nlev_len(),
            context.parameters().blind_rotation().nlev_len()
        );
        assert_eq!(
            candidate.key_switching().basis().decompose_length().get(),
            context_parameters
                .key_switching()
                .basis()
                .decompose_length()
                .get()
        );
        let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
        let incompatible_parameters = &candidate;
        let incompatible = TfheContext::try_new(incompatible_parameters.clone(), table).unwrap();
        let expected = if key_switching_log_basis != 8 {
            TfheEvaluationError::IncompatibleLweReturnKey
        } else {
            TfheEvaluationError::IncompatibleBlindRotationKey
        };
        assert_eq!(
            incompatible.evaluator(&server_key).err(),
            Some(expected.clone())
        );
        assert_eq!(
            incompatible.boolean_evaluator(&server_key).err(),
            Some(expected.clone())
        );
    }
}

/// Configured capabilities fail before sampling, share one BR domain, and bind
/// independently supplied keys using the retained gadget/input choices.
#[test]
fn operation_state_controls_material_and_binding() {
    use primus_tfhe_ntru_fourier::{CbsGadgetConfig, DecompositionConfig, KeyGenerationError};
    use rand::RngExt;

    let parameters = parameters(8, 8);
    let context = TfheContext::<_, RustFftTable>::from_parameters(parameters.clone());
    assert!(matches!(
        context.compile_cbs_identity(),
        Err(TfheEvaluationError::MissingCircuitBootstrapParameters)
    ));
    let mut rng = StdRng::seed_from_u64(0x4341504142494c49);
    let mut untouched = StdRng::seed_from_u64(0x4341504142494c49);
    assert!(matches!(
        context.try_generate_circuit_bootstrap_keys(&mut rng),
        Err(KeyGenerationError::MissingCircuitBootstrapParameters)
    ));
    assert_eq!(rng.random::<u64>(), untouched.random::<u64>());

    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let gadget = CbsGadgetConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(2)),
        },
        trace: full,
        scheme_switch: full,
    };
    let context = context.try_with_circuit_bootstrap(gadget).unwrap();
    assert_eq!(context.parameters().messages(), parameters.messages());
    let (_, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    // t=3 and t=4 have the same number of unsigned inputs, but different
    // Rounded intervals. The configured workflow must reject that pairing.
    context.circuit_bootstrap_evaluator(&server).unwrap();
    let other_input =
        primus_encoding::RoundedCodec::new(3, context.parameters().external_lwe().cipher_modulus());
    let other_program = context
        .cbs_parameters()
        .unwrap()
        .gadget()
        .compile_lookup_table(&other_input)
        .unwrap();
    assert_eq!(
        other_program.input_domain_len(),
        context.compile_cbs_identity().unwrap().input_domain_len()
    );
    assert!(matches!(
        context.circuit_bootstrap_evaluator_with_lookup_table(&server, other_program),
        Err(TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
    let circuit = server.circuit_bootstrap_key();
    let pbs = context.evaluator(server.server_key()).unwrap();
    context
        .circuit_bootstrap_evaluator_with_resources(pbs.bootstrap_resources(), circuit)
        .unwrap();

    // Complete CBS parameters retain configured return KS, so restoring the
    // context also retains ordinary PBS. Mutable resources remain context-bound.
    let restored = TfheContext::<_, RustFftTable>::from_cbs_parameters(
        context.cbs_parameters().unwrap().clone(),
    );

    let restored_pbs = restored.evaluator(server.server_key()).unwrap();
    restored
        .circuit_bootstrap_evaluator_with_resources(restored_pbs.bootstrap_resources(), circuit)
        .unwrap();
    assert!(matches!(
        restored.circuit_bootstrap_evaluator_with_resources(pbs.bootstrap_resources(), circuit),
        Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters)
    ));

    // Equal rings are insufficient when independent operation state selected
    // another BR algorithm; the discrepancy is rejected during context setup.
    let different_algorithm =
        parameters
            .as_ref()
            .clone()
            .with_algorithm(primus_tfhe::BlindRotationMethod::Sparse {
                copy_count: 3,
                bucket_count: 4,
            });
    let different =
        primus_tfhe_ntru::CbsParameters::try_with_config(different_algorithm, gadget).unwrap();
    assert!(matches!(
        TfheContext::<_, RustFftTable>::from_parameters(parameters.clone())
            .try_with_cbs_parameters(different),
        Err(primus_tfhe_ntru_fourier::TfheContextError::Parameters(
            primus_tfhe_ntru_fourier::TfheParameterError::IncompatibleComponents
        ))
    ));
}
