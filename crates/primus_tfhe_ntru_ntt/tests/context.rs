use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_lattice::LweDimension;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::PolyLength;
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, GadgetEncryptionConfig, PbsParameters, TfheContext, TfheEvaluationError,
};
use rand::{SeedableRng, rngs::StdRng};
use std::error::Error;

const POLY_LENGTH: usize = 32;
const LWE_DIMENSION: usize = 4;
const PLAIN_MODULUS: u32 = 4;
const CIPHER_MODULUS: u32 = 132_120_577;

fn parameters(
    cipher_modulus: u32,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
) -> PbsParameters<u32> {
    let modulus = BarrettModulus::new(cipher_modulus);

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
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(key_switching_log_basis),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        algorithm: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(PLAIN_MODULUS),
    })
    .unwrap()
}

#[test]
fn rejects_server_keys_with_same_layout_but_different_bases_or_modulus() {
    let original = parameters(CIPHER_MODULUS, 9, 9);
    let table = U32NttTable::new(
        PolyLength::new(POLY_LENGTH),
        original.as_ref().accumulator_ntru().cipher_modulus(),
    )
    .unwrap();
    let context_parameters = &original;
    let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4e54_5255_4241_5349);
    let (_, server_key) = context.try_generate_keys(&mut rng).unwrap();

    assert!(context.evaluator(&server_key).is_ok());

    // Both moduli have 27 bits; bases 2^8 and 2^9 both retain three levels.
    // Shape checks alone therefore accept all of these incompatible keys.
    for (cipher_modulus, bootstrapping_log_basis, key_switching_log_basis) in [
        (CIPHER_MODULUS, 8, 9),
        (CIPHER_MODULUS, 9, 8),
        (104_857_601, 9, 9),
    ] {
        let candidate = parameters(
            cipher_modulus,
            bootstrapping_log_basis,
            key_switching_log_basis,
        );
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
        let table = U32NttTable::new(
            PolyLength::new(POLY_LENGTH),
            candidate.as_ref().accumulator_ntru().cipher_modulus(),
        )
        .unwrap();
        let incompatible_parameters = &candidate;
        let incompatible = TfheContext::try_new(incompatible_parameters.clone(), table).unwrap();

        let expected = if cipher_modulus != CIPHER_MODULUS || key_switching_log_basis != 9 {
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

#[test]
fn construction_errors_preserve_transform_sources() {
    use primus_ntru::{NtruError, NtruSecretKey};
    use primus_tfhe_ntru_ntt::{
        ClientKey, KeyGenerationError, KeyGenerator, TfheClientError, TfheContextError,
    };

    let error_parameters = &parameters(19, 2, 2);
    let error = TfheContext::<_, U32NttTable>::try_from_parameters(error_parameters.clone())
        .err()
        .unwrap();
    assert!(matches!(&error, TfheContextError::TransformTable(_)));
    assert!(error.source().unwrap().is::<primus_ntt::NttError<u32>>());

    let context_parameters = &parameters(CIPHER_MODULUS, 9, 9);
    let context =
        TfheContext::<_, U32NttTable>::try_from_parameters(context_parameters.clone()).unwrap();
    // Compatible shape/distributions do not imply an invertible secret.
    let client = ClientKey::new(
        primus_lwe::LweSecretKey::new(
            (vec![0; POLY_LENGTH])[..LWE_DIMENSION]
                .iter()
                .map(|&s| {
                    if s < Default::default() {
                        context
                            .parameters()
                            .external_lwe()
                            .cipher_modulus_minus_one()
                    } else {
                        primus_integer::SignedInteger::cast_to_unsigned(s)
                    }
                })
                .collect(),
            SecretKeyDistr::UniformBinary,
            context.parameters().external_lwe().cipher_modulus(),
        ),
        NtruSecretKey::new(vec![0; POLY_LENGTH], SecretKeyDistr::SparseTernary),
    );
    assert_eq!(
        context
            .accumulator_client(client.accumulator_ntru_secret_key(), 4)
            .err(),
        Some(TfheClientError::Ntru(NtruError::NonInvertibleSecretKey))
    );
    let error = KeyGenerator::new(&context)
        .try_generate_server_key_with_parameters(
            context_parameters.key_switching(),
            &client,
            BlindRotationMethod::Classic,
            &mut StdRng::seed_from_u64(42),
        )
        .err()
        .unwrap();
    assert_eq!(
        error,
        KeyGenerationError::Ntru(NtruError::NonInvertibleSecretKey)
    );
    assert_eq!(
        error.source().unwrap().downcast_ref::<NtruError>(),
        Some(&NtruError::NonInvertibleSecretKey)
    );
}

/// Configured capabilities fail before sampling, share one BR domain, and bind
/// independently supplied keys using the retained gadget/input choices.
#[test]
fn operation_state_controls_material_and_binding() {
    use primus_tfhe_ntru_ntt::{CbsGadgetConfig, DecompositionConfig, KeyGenerationError};
    use rand::RngExt;

    let parameters = parameters(CIPHER_MODULUS, 9, 9);
    let context = TfheContext::<_, U32NttTable>::try_from_parameters(parameters.clone()).unwrap();
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
    let restored = TfheContext::<_, U32NttTable>::try_from_cbs_parameters(
        context.cbs_parameters().unwrap().clone(),
    )
    .unwrap();

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
        TfheContext::<_, U32NttTable>::try_from_parameters(parameters.clone())
            .unwrap()
            .try_with_cbs_parameters(different),
        Err(primus_tfhe_ntru_ntt::TfheContextError::Parameters(
            primus_tfhe_ntru_ntt::TfheParameterError::IncompatibleComponents
        ))
    ));
}
