//! Context/table and decomposition binding, plus independently created
//! client/server keys in both GLWE PBS orders.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{
    GlevParameters, GlweEncryptionParameters, NttGlweGadgetEncryptWorkspace,
    NttGlweKeySwitchingKey, NttGlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, LweDimension};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use primus_tfhe_glwe_ntt::{
    ClientKey, GadgetEncryptionConfig, KeyGenerator, PbsOrder, PbsParameters, TfheContext,
    TfheContextError, TfheEvaluationError,
};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

const POLY_LENGTH: usize = 32;
const MODULUS: u32 = 132_120_577;
// Distinct from BR and fresh LWE sigma=0.7 to expose accidental role coupling.
const KS_SIGMA: f64 = 1.25;

fn parameters(order: PbsOrder) -> PbsParameters<u32> {
    parameters_with_bases(order, 8, 4, SecretKeyDistr::UniformBinary)
}

fn parameters_with_bases(
    order: PbsOrder,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
    distribution: SecretKeyDistr,
) -> PbsParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: modulus.into(),
            secret_key_distr: distribution,
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(POLY_LENGTH),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(bootstrapping_log_basis),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(key_switching_log_basis),
                level_count: Some(DecompositionLevelCount::new(4)),
            },
            noise_standard_deviation: KS_SIGMA,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(4),
        order,
    })
    .unwrap()
}

#[test]
fn ordinary_clients_do_not_prepare_unused_mvb_encoding() {
    // Rounded permits this output domain; Scaled cannot recover its centers.
    // No server material is needed to test client binding and public compilation.
    let messages = PbsMessageConfig::new(4).with_output_modulus(MODULUS - 1);
    let parameters = parameters(PbsOrder::BootstrapKeyswitch).with_messages(messages);
    let context = TfheContext::<u32, U32NttTable>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0x434f_4445_4353);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let secret = client.external_lwe_secret_key();
    let encryptor = context.encryptor(secret).unwrap();
    let decryptor = context.pbs_decryptor(secret).unwrap();
    let input = encryptor.encrypt_padded(1, &mut rng).unwrap();
    let phase = decryptor.decrypt_phase(input.as_view()).unwrap();
    assert_eq!(
        primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus())
            .decode_value(phase),
        1
    );
    context
        .pbs_lookup_table_compiler()
        .unwrap()
        .compile_fn(|_| 0)
        .unwrap();
    assert!(matches!(
        context.mvb_decryptor(secret),
        Err(primus_tfhe_glwe_ntt::TfheClientError::Client(
            primus_tfhe::ClientError::Encoding(
                primus_encoding::CodecError::InsufficientScaleRecovery
            )
        ))
    ));
    assert!(context.compile_mvb_fn(2, 1, |_, _| 0).is_err());
}

#[test]
fn server_keys_are_bound_to_their_decomposition_bases() {
    let modulus = BarrettModulus::new(MODULUS);
    let source_table = U32NttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
    let source_parameters = &parameters(PbsOrder::BootstrapKeyswitch);
    let source = TfheContext::try_new(source_parameters.clone(), source_table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4241_5349_534b_4559);
    let (_, server_key) = source.try_generate_keys(&mut rng).unwrap();

    for (br_log, ks_log, distribution, expected) in [
        (
            7,
            4,
            SecretKeyDistr::UniformBinary,
            TfheEvaluationError::IncompatibleBlindRotationKey,
        ),
        (
            8,
            5,
            SecretKeyDistr::UniformBinary,
            TfheEvaluationError::IncompatibleGlweKeySwitchingKey,
        ),
        (
            8,
            4,
            SecretKeyDistr::UniformTernary,
            TfheEvaluationError::IncompatibleBlindRotationKey,
        ),
    ] {
        let parameters =
            parameters_with_bases(PbsOrder::BootstrapKeyswitch, br_log, ks_log, distribution);
        let table = U32NttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
        let context_parameters = &parameters;
        let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();
        assert_eq!(context.evaluator(&server_key).err().unwrap(), expected);
    }
}

#[test]
fn rejects_incompatible_ntt_tables() {
    let modulus = BarrettModulus::new(MODULUS);
    let wrong_length = U32NttTable::new(PolyLength::new(POLY_LENGTH * 2), modulus).unwrap();
    let error_parameters = &parameters(PbsOrder::BootstrapKeyswitch);
    let error = TfheContext::try_new(error_parameters.clone(), wrong_length)
        .err()
        .expect("the length mismatch must be rejected");
    assert!(matches!(error,
        TfheContextError::PolynomialLengthMismatch { expected: POLY_LENGTH, actual }
        if actual == POLY_LENGTH * 2
    ));

    const OTHER_MODULUS: u32 = 998_244_353;
    let wrong_modulus = U32NttTable::new(
        PolyLength::new(POLY_LENGTH),
        BarrettModulus::new(OTHER_MODULUS),
    )
    .unwrap();
    let error_parameters = &parameters(PbsOrder::BootstrapKeyswitch);
    let error = TfheContext::try_new(error_parameters.clone(), wrong_modulus)
        .err()
        .expect("the modulus mismatch must be rejected");
    assert!(matches!(
        error,
        TfheContextError::ModulusMismatch {
            expected: MODULUS,
            actual: OTHER_MODULUS
        }
    ));
}

#[test]
fn split_keys_support_both_pbs_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let modulus = BarrettModulus::new(MODULUS);
        let table = U32NttTable::new(PolyLength::new(POLY_LENGTH), modulus).unwrap();
        let context_parameters = &parameters_with_bases(
            order,
            8,
            4,
            SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
        );
        let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();
        let input_codec =
            primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
        let mut rng = StdRng::seed_from_u64(43);
        // Fresh key generation is covered by the PBS and Boolean tests.
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let blind_rotation = generator
            .try_generate_blind_rotation_key(
                &client,
                primus_tfhe_glwe_ntt::BlindRotationMethod::Classic,
                &mut rng,
            )
            .unwrap();
        let mut key_rng = StdRng::seed_from_u64(44);
        let mut reference_rng = StdRng::seed_from_u64(44);
        let key_switching = generator
            .try_generate_glwe_key_switching_key(
                context_parameters.glwe_key_switching(),
                &client,
                &mut key_rng,
            )
            .unwrap();
        check_key_switching_noise(
            context_parameters,
            &context,
            &client,
            &key_switching,
            &mut reference_rng,
        );
        let server = primus_tfhe_glwe_ntt::ServerKey::new(blind_rotation, key_switching);
        let codecs = context
            .parameters()
            .pbs_codecs(PbsMessageConfig::new(input_codec.plaintext_modulus()))
            .unwrap();
        let lookup_table = context
            .parameters()
            .lookup_table_compiler(&codecs)
            .unwrap()
            .compile_slice(&[1u32, 0])
            .unwrap();
        let public = context
            .parameters()
            .try_generate_public_key(client.external_lwe_secret_key(), &mut rng)
            .unwrap();
        let secret_encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
        let public_encryptor = context.public_encryptor(&public).unwrap();
        let decryptor = context
            .pbs_decryptor(client.external_lwe_secret_key())
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        for message in 0..2u32 {
            for input in [
                secret_encryptor.encrypt_padded(message, &mut rng).unwrap(),
                public_encryptor.encrypt_padded(message, &mut rng).unwrap(),
            ] {
                let output = evaluator.apply_lookup_table(input.as_view(), &lookup_table);
                assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), 1 - message);
            }
        }
        let boolean_encryptor = context.boolean_public_encryptor(&public).unwrap();
        let boolean_decryptor = context
            .boolean_decryptor(client.external_lwe_secret_key())
            .unwrap();
        let mut boolean_evaluator = context.boolean_evaluator(&server).unwrap();
        let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
        let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
        assert!(
            boolean_decryptor
                .decrypt(
                    boolean_evaluator
                        .xor(lhs.as_view(), rhs.as_view())
                        .as_view()
                )
                .unwrap()
        );
    }
}

/// Rebuilds KS rows with an independently specified sampler and the same coins.
/// Exact key equality detects using BR/fresh-LWE noise even when PBS still decodes.
fn check_key_switching_noise(
    context_parameters: &PbsParameters<u32>,
    context: &TfheContext<u32, U32NttTable>,
    client: &ClientKey<u32>,
    actual: &NttGlweKeySwitchingKey<u32>,
    rng: &mut StdRng,
) {
    let output = context_parameters.glwe_key_switching().output();
    let expected_parameters = GlevParameters::try_from_parts(
        output.glwe_size(),
        Arc::new(GlweEncryptionParameters::new(
            context.parameters().cipher_modulus(),
            output.secret_key_distr(),
            KS_SIGMA,
        )),
        output.basis().clone(),
    )
    .unwrap();
    let secret = client.padded_small_glwe_secret_key(context.parameters());
    let secret = NttGlweSecretKey::from_coeff_secret_key(&secret, context.table());
    let mut workspace = NttGlweGadgetEncryptWorkspace::new(expected_parameters.size());
    let expected = NttGlweKeySwitchingKey::generate(
        client.glwe_secret_key(),
        &secret,
        &expected_parameters,
        context.table(),
        rng,
        &mut workspace,
    );
    assert_eq!(actual.as_slice(), expected.as_slice());
}

/// Configured capabilities fail before sampling, share one BR domain, and bind
/// independently supplied keys using the retained gadget/input choices.
#[test]
fn operation_state_controls_material_and_binding() {
    use primus_tfhe_glwe_ntt::{CbsGadgetConfig, DecompositionConfig, KeyGenerationError};
    use rand::RngExt;

    let parameters = parameters(PbsOrder::KeyswitchBootstrap);
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
    // KS sigma differs from BR sigma in this fixture. The CBS input stage
    // must reuse that independently chosen KS state in KS→BR order.
    let input = context
        .cbs_parameters()
        .unwrap()
        .pbs_parameters()
        .input_key_switching()
        .unwrap();
    assert_eq!(input.output().noise_standard_deviation(), KS_SIGMA);
    let (_, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    // t=3 and t=4 have the same number of unsigned inputs, but different
    // Rounded intervals. The configured workflow must reject that pairing.
    context.circuit_bootstrap_evaluator(&server).unwrap();
    let other_input = primus_encoding::RoundedCodec::new(3, context.parameters().cipher_modulus());
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

    // Complete CBS parameters retain the configured KS, so restoring the
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
    let different_algorithm = parameters.as_ref().clone().with_blind_rotation_method(
        primus_tfhe::BlindRotationMethod::Sparse {
            copy_count: 3,
            bucket_count: 4,
        },
    );
    let different =
        primus_tfhe_glwe::CbsParameters::try_with_config(different_algorithm, gadget).unwrap();
    assert!(matches!(
        TfheContext::<_, U32NttTable>::try_from_parameters(parameters.clone())
            .unwrap()
            .try_with_cbs_parameters(different),
        Err(primus_tfhe_glwe_ntt::TfheContextError::Parameters(
            primus_tfhe_glwe_ntt::TfheParameterError::IncompatibleComponents
        ))
    ));
}
