//! Context/table and decomposition binding, plus independently created
//! client/server keys in both GLWE PBS orders.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::{
    FourierGlweGadgetEncryptWorkspace, FourierGlweKeySwitchingKey, FourierGlweSecretKey,
    GadgetSize, GlevParameters, GlweCiphertext, GlweEncryptionParameters, SecretKeyDistr,
};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_poly::{PolyLength, Polynomial};
use primus_tfhe::PbsMessageConfig;
use primus_tfhe_glwe_fourier::{
    BlindRotationKey, ClientKey, FourierGlweBlindRotationWorkspace, GadgetEncryptionConfig,
    KeyGenerator, PbsOrder, PbsParameters, TfheContext, TfheContextError, TfheEvaluationError,
};

use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

const POLY_LENGTH: usize = 32;
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
    PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: NativeModulus::new().into(),
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
fn rejects_a_fourier_table_with_the_wrong_length() {
    let table = RustFftTable::new(PolyLength::new(POLY_LENGTH * 2));
    let error_parameters = &parameters(PbsOrder::BootstrapKeyswitch);
    let error = TfheContext::try_new(error_parameters.clone(), table)
        .err()
        .expect("the mismatched table must be rejected");

    assert!(matches!(error,
        TfheContextError::PolynomialLengthMismatch { expected: POLY_LENGTH, actual }
        if actual == POLY_LENGTH * 2
    ));
}

#[test]
fn split_keys_support_both_pbs_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
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
                primus_tfhe_glwe_fourier::BlindRotationMethod::Classic,
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
        let server = primus_tfhe_glwe_fourier::ServerKey::new(blind_rotation, key_switching);
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
        let boolean_encryptor = context
            .boolean_public_encryptor(&public, &input_codec)
            .unwrap();
        let boolean_decryptor = context
            .boolean_decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let mut boolean_evaluator = context.boolean_evaluator(&server, &input_codec).unwrap();
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
/// Both generators use the same FFT table, so their transformed keys agree exactly.
fn check_key_switching_noise(
    context_parameters: &PbsParameters<u32>,
    context: &TfheContext<u32, RustFftTable>,
    client: &ClientKey<u32>,
    actual: &FourierGlweKeySwitchingKey<u32>,
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
    let mut fft = context.new_fft_engine();
    let secret = client.padded_small_glwe_secret_key(context.parameters());
    let secret = FourierGlweSecretKey::from_coeff_secret_key(&secret, &mut fft);
    let mut workspace = FourierGlweGadgetEncryptWorkspace::new(expected_parameters.size());
    let expected = FourierGlweKeySwitchingKey::generate(
        client.glwe_secret_key(),
        &secret,
        &expected_parameters,
        &mut fft,
        rng,
        &mut workspace,
    );
    assert_eq!(actual.as_slice(), expected.as_slice());
}

#[test]
fn server_keys_are_bound_to_both_decomposition_bases() {
    let source_parameters = &parameters(PbsOrder::BootstrapKeyswitch);
    let source = TfheContext::try_new(
        source_parameters.clone(),
        RustFftTable::new(PolyLength::new(POLY_LENGTH)),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
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
        let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
        let context_parameters = &parameters;
        let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();
        assert_eq!(context.evaluator(&server_key).err().unwrap(), expected);
    }
}

#[test]
fn public_blind_rotation_rejects_mismatches_before_output_writes() {
    let context_parameters = &parameters(PbsOrder::BootstrapKeyswitch);
    let context = TfheContext::try_new(
        context_parameters.clone(),
        RustFftTable::new(PolyLength::new(POLY_LENGTH)),
    )
    .unwrap();

    let mut rng = StdRng::seed_from_u64(42);
    let (_, server_key) = context.try_generate_keys(&mut rng).unwrap();
    let BlindRotationKey::Classic(key) = server_key.blind_rotation_key() else {
        panic!("raw classic rotation test requires a classic key");
    };
    let size = key.size();
    let input_len = key.input_dimension().ciphertext_len();
    let glwe_len = size.glwe_len();
    let input = LweCiphertext::new(vec![0u32; input_len]);
    let accumulator = GlweCiphertext::<Vec<u32>>::zero(glwe_len);
    let mut fft = context.new_fft_engine();
    let mut scratch = FourierGlweBlindRotationWorkspace::new(key);

    // Both accumulator entry points share the same checked rotation wrapper.
    for (input_len, accumulator_len, output_len) in [
        (input_len - 1, glwe_len, glwe_len),
        (input_len, glwe_len - 1, glwe_len),
        (input_len, glwe_len, glwe_len - 1),
    ] {
        let input = LweCiphertext::new(vec![0u32; input_len]);
        let accumulator = GlweCiphertext::<Vec<u32>>::zero(accumulator_len);
        for exponents in [false, true] {
            let mut output = GlweCiphertext::new(vec![17u32; output_len]);
            let before = output.as_ref().to_vec();
            let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if exponents {
                    key.fourier_blind_rotate_exponents_to(
                        &input,
                        &accumulator,
                        &mut output,
                        &mut fft,
                        &mut scratch,
                    );
                } else {
                    key.fourier_blind_rotate_to(
                        &input,
                        &accumulator,
                        &mut output,
                        &mut fft,
                        &mut scratch,
                    );
                }
            }));
            assert!(rejected.is_err());
            assert_eq!(output.as_ref(), before);
        }
    }

    // Raw LUT APIs own their checks independently of the evaluator's metadata.
    for (input_len, lookup_len, output_len, rotation_step) in [
        (input_len - 1, POLY_LENGTH, glwe_len, None),
        (input_len, POLY_LENGTH - 1, glwe_len, None),
        (input_len, POLY_LENGTH, glwe_len - 1, None),
        (input_len - 1, POLY_LENGTH, glwe_len, Some(2)),
        (input_len, POLY_LENGTH - 1, glwe_len, Some(2)),
        (input_len, POLY_LENGTH, glwe_len - 1, Some(2)),
        (input_len, POLY_LENGTH, glwe_len, Some(0)),
        (input_len, POLY_LENGTH, glwe_len, Some(3)),
        (input_len, POLY_LENGTH, glwe_len, Some(POLY_LENGTH * 2)),
    ] {
        let input = LweCiphertext::new(vec![0u32; input_len]);
        let lookup = Polynomial::<Vec<u32>>::zero(lookup_len);
        let mut output = GlweCiphertext::new(vec![17u32; output_len]);
        let before = output.as_ref().to_vec();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(rotation_step) = rotation_step {
                key.fourier_blind_rotate_interleaved_lookup_table_to(
                    &input,
                    &lookup,
                    rotation_step,
                    &mut output,
                    &mut fft,
                    &mut scratch,
                );
            } else {
                key.fourier_blind_rotate_lookup_table_to(
                    &input,
                    &lookup,
                    &mut output,
                    &mut fft,
                    &mut scratch,
                );
            }
        }));
        assert!(rejected.is_err());
        assert_eq!(output.as_ref(), before);
    }

    let wrong_table = RustFftTable::new(PolyLength::new(POLY_LENGTH * 2));
    let mut wrong_fft = primus_fft::FftEngine::new(&wrong_table);
    let mut wrong_scratch = FourierGlweBlindRotationWorkspace::new(key);
    wrong_scratch.resize(GadgetSize::new(
        size.glwe_size(),
        DecompositionLevelCount::new(size.decompose_length().get() + 1),
    ));
    // All data have valid lengths here, so resource mismatch alone must reject.
    for (fft, scratch) in [
        (&mut wrong_fft, &mut scratch),
        (&mut fft, &mut wrong_scratch),
    ] {
        let mut output = GlweCiphertext::new(vec![17u32; glwe_len]);
        let before = output.as_ref().to_vec();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key.fourier_blind_rotate_to(&input, &accumulator, &mut output, fft, scratch);
        }));
        assert!(rejected.is_err());
        assert_eq!(output.as_ref(), before);
    }
}

/// Configured capabilities fail before sampling, share one BR domain, and bind
/// independently supplied keys using the retained gadget/input choices.
#[test]
fn operation_state_controls_material_and_binding() {
    use primus_tfhe_glwe_fourier::{CbsGadgetConfig, DecompositionConfig, KeyGenerationError};
    use rand::RngExt;

    let parameters = parameters(PbsOrder::KeyswitchBootstrap);
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
    let different_algorithm = parameters.as_ref().clone().with_blind_rotation_method(
        primus_tfhe::BlindRotationMethod::Sparse {
            copy_count: 3,
            bucket_count: 4,
        },
    );
    let different =
        primus_tfhe_glwe::CbsParameters::try_with_config(different_algorithm, gadget).unwrap();
    assert!(matches!(
        TfheContext::<_, RustFftTable>::from_parameters(parameters.clone())
            .try_with_cbs_parameters(different),
        Err(primus_tfhe_glwe_fourier::TfheContextError::Parameters(
            primus_tfhe_glwe_fourier::TfheParameterError::IncompatibleComponents
        ))
    ));
}
