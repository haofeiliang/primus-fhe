use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::ggsw::NttGgsw;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::U64NttTable;
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe::ProgrammableBootstrap as _;
use primus_tfhe_glwe_ntt::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameters,
    DecompositionConfig, KeyGenerator, PbsOrder, TfheContext, TfheEvaluationError, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const POLY_LENGTH: usize = 256;
const MODULUS: u64 = 1_125_899_906_826_241;

fn parameters(
    order: PbsOrder,
    plain_modulus: u64,
    distribution: SecretKeyDistr,
) -> TfheParameters<u64> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, plain_modulus, modulus, distribution, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        plain_modulus,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    // Full decomposition keeps the phase error below the third output level.
    let bootstrapping = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 10, None);
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 10, Some(4)),
        order,
    )
    .unwrap()
}

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    for (order, distribution, sparse) in [
        (
            PbsOrder::BootstrapKeyswitch,
            SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
            false,
        ),
        (
            PbsOrder::BootstrapKeyswitch,
            SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
            true,
        ),
        (
            PbsOrder::KeyswitchBootstrap,
            SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
            true,
        ),
        (
            PbsOrder::BootstrapKeyswitch,
            SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
            false,
        ),
        (
            PbsOrder::KeyswitchBootstrap,
            SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
            false,
        ),
    ] {
        let tfhe = parameters(order, 4, distribution);
        let modulus = BarrettModulus::new(MODULUS);
        let context = TfheContext::<_, U64NttTable>::try_from_parameters(tfhe).unwrap();
        let mut rng = StdRng::seed_from_u64(0x0050_4154_4348_4544 ^ order as u64);
        // Three gadget levels exercise multiple scales and an internal padding slot.
        let levels = 3;
        let cbs_config = CircuitBootstrapConfig {
            output: DecompositionConfig {
                log_basis: 8,
                level_count: Some(levels),
            },
            trace: DecompositionConfig {
                log_basis: 10,
                level_count: None,
            },
            trace_noise_standard_deviation: 0.7,
            scheme_switch: DecompositionConfig {
                log_basis: 10,
                level_count: None,
            },
            scheme_switch_noise_standard_deviation: 0.7,
        };
        let (client_key, classic_server_key) = context
            .try_generate_keys(Some(cbs_config), &mut rng)
            .unwrap();
        let sparse_server_key = sparse.then(|| {
            // Bundled generation and separately paired CBS material share the same evaluator.
            let config = (order == PbsOrder::BootstrapKeyswitch).then_some(cbs_config);
            KeyGenerator::new(&context)
                .try_generate_sparse_server_key(&client_key, 3, 4, config, &mut rng)
                .unwrap()
        });
        let server_key = sparse_server_key.as_ref().unwrap_or(&classic_server_key);
        if sparse && order == PbsOrder::KeyswitchBootstrap {
            assert!(matches!(
                context.circuit_bootstrap_evaluator(server_key),
                Err(TfheEvaluationError::MissingCircuitBootstrapKey)
            ));
        }
        let circuit_key = server_key
            .circuit_bootstrap_key()
            .unwrap_or_else(|| classic_server_key.circuit_bootstrap_key().unwrap());
        let circuit_parameters = circuit_key.parameters();
        let main_secret =
            NttGlweSecretKey::from_coeff_secret_key(client_key.glwe_secret_key(), context.table());
        let glwe = context.parameters().accumulator_glwe();
        let mut accumulator_client = context.accumulator_client(&client_key).unwrap();
        let messages = [0u64, 1].map(|offset| {
            (0..POLY_LENGTH)
                .map(|i| (i as u64 + offset) % 4)
                .collect::<Vec<_>>()
        });
        let choices = messages.each_ref().map(|message| {
            let mut output = context.allocate_accumulator_ciphertext();
            let (_, allocation) = allocations::measure(|| {
                accumulator_client.encrypt_to(message, &mut output, &mut rng)
            });
            assert_eq!(
                allocation.count, 0,
                "accumulator encryption must reuse its workspace"
            );
            output
        });

        let encryptor = context.encryptor(&client_key).unwrap();
        // The same CBS-enabled server key also supports ordinary PBS.
        let identity = context
            .parameters()
            .compile_lookup_table_fn(|message| message as u64)
            .unwrap();
        let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
        let mut output = context
            .evaluator(server_key)
            .unwrap()
            .apply_lookup_table(&input, &identity);
        assert_eq!(
            context
                .decryptor(&client_key)
                .unwrap()
                .decrypt(&output)
                .unwrap(),
            1
        );

        let other_context = TfheContext::<_, U64NttTable>::try_from_parameters(parameters(
            order,
            4,
            SecretKeyDistr::UniformBinary,
        ))
        .unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_from_parts(
                &other_context,
                server_key,
                circuit_parameters,
                circuit_key
            ),
            Err(TfheEvaluationError::IncompatibleServerKey)
        ));
        let other_input_domain = CircuitBootstrapParameters::try_new(
            &parameters(order, 8, distribution),
            circuit_parameters.output_basis().clone(),
            circuit_parameters.trace().clone(),
            circuit_parameters.scheme_switch().clone(),
        )
        .unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_from_parts(
                &context,
                server_key,
                &other_input_domain,
                circuit_key,
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapParameters)
        ));
        let incompatible_trace =
            GgswParameters::with_glwe_params(context.parameters().accumulator_glwe(), 9, None);
        let incompatible_parameters = CircuitBootstrapParameters::try_new(
            context.parameters(),
            circuit_parameters.output_basis().clone(),
            incompatible_trace,
            circuit_parameters.scheme_switch().clone(),
        )
        .unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_from_parts(
                &context,
                server_key,
                &incompatible_parameters,
                circuit_key
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        // GLWE scheme switching binds output layout, so another output basis
        // with the same level count can reuse this circuit key.
        let alternate = CircuitBootstrapParameters::try_new(
            context.parameters(),
            ApproxSignedBasis::new(Some(MODULUS), if sparse { 8 } else { 9 }, Some(levels)),
            circuit_parameters.trace().clone(),
            circuit_parameters.scheme_switch().clone(),
        )
        .unwrap();
        let (circuit_parameters, mut evaluator) = match order {
            PbsOrder::BootstrapKeyswitch => (circuit_parameters, {
                let mut standalone = context.circuit_bootstrap_evaluator(server_key).unwrap();
                assert!(standalone.bootstrapper_mut().is_none());
                // Exercise the missing-KS form before recovery fills that workspace.
                let mut control = standalone.allocate_output();
                let mut selected = context.allocate_accumulator_ciphertext();
                let mut decoded = vec![0; POLY_LENGTH];
                let (_, online) = allocations::measure(|| {
                    standalone.circuit_bootstrap_to(&input, &mut control);
                    standalone.cmux_to(&control, &choices[0], &choices[1], &mut selected);
                });
                assert_eq!(online.count, 0, "standalone BK CBS/CMUX must not allocate");
                accumulator_client.decrypt_to(&selected, &mut decoded);
                assert_eq!(decoded, messages[1]);
                let (pbs, allocation) = allocations::measure(|| standalone.into_bootstrapper());
                assert!(
                    allocation.count > 0,
                    "standalone BK recovery explicitly creates return-KS scratch"
                );
                CircuitBootstrapEvaluator::try_from_bootstrapper(pbs).unwrap()
            }),
            PbsOrder::KeyswitchBootstrap => (
                &alternate,
                CircuitBootstrapEvaluator::try_from_parts(
                    &context,
                    server_key,
                    &alternate,
                    circuit_key,
                )
                .unwrap(),
            ),
        };
        assert_eq!(
            circuit_parameters.lookup_table_padded_output_count(),
            levels.next_power_of_two()
        );
        let mut control = evaluator.allocate_output();
        let mut selected = context.allocate_accumulator_ciphertext();
        let mut product = context.allocate_accumulator_ciphertext();
        let mut decoded = vec![0; POLY_LENGTH];
        let mut decoded_product = vec![0; POLY_LENGTH];
        // A zero result must overwrite the previous nonzero control.
        for bit in [1u64, 0] {
            let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
            if bit == 1 {
                for (dimension, length) in [
                    (input.dimension() - 1, control.as_ref().len()),
                    (input.dimension(), control.as_ref().len() - 1),
                ] {
                    let bad_input = LweCiphertext::zero(dimension);
                    let mut bad_output = NttGgsw::new(vec![7; length]);
                    assert!(
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            evaluator.circuit_bootstrap_to(&bad_input, &mut bad_output);
                        }))
                        .is_err()
                    );
                    assert!(bad_output.as_ref().iter().all(|&value| value == 7));
                }
            }
            let (_, allocation) = allocations::measure(|| {
                evaluator.circuit_bootstrap_to(&input, &mut control);
                evaluator.cmux_to(&control, &choices[0], &choices[1], &mut selected);
                evaluator.external_product_to(&control, &choices[1], &mut product);
                evaluator.bootstrapper_mut().unwrap().apply_lookup_table_to(
                    &input,
                    &identity,
                    &mut output,
                );
                accumulator_client.decrypt_to(&selected, &mut decoded);
                accumulator_client.decrypt_to(&product, &mut decoded_product);
            });
            assert_eq!(
                context
                    .decryptor(&client_key)
                    .unwrap()
                    .decrypt(&output)
                    .unwrap(),
                bit
            );
            assert_eq!(allocation.count, 0, "CBS must reuse its workspace");
            let output_size = circuit_parameters.output_size();
            let mut phase = Polynomial::new(vec![0u64; POLY_LENGTH]);
            for (row, glev) in control.iter_ntt_glev(output_size.glev_len()).enumerate() {
                let secret = client_key.glwe_secret_key().iter().nth(row);
                for (scalar, level) in circuit_parameters
                    .output_basis()
                    .scalar_iter()
                    .zip(glev.iter_ntt_glwe(glwe.glwe_len()))
                {
                    main_secret.phase_to(&level, &mut phase, modulus, context.table());
                    for (index, &actual) in phase.as_ref().iter().enumerate() {
                        // Mask rows encrypt -g_l * bit * s_r; the body row
                        // encrypts the constant g_l * bit, with a zero tail.
                        let coefficient =
                            secret.map_or(i128::from(index == 0), |s| -i128::from(s[index]));
                        let expected = (coefficient * i128::from(scalar) * i128::from(bit))
                            .rem_euclid(i128::from(MODULUS))
                            as u64;
                        let distance = actual.abs_diff(expected);
                        let distance = distance.min(MODULUS - distance);
                        // Functional fixture bound, below the smallest gadget step.
                        assert!(
                            distance < scalar / 8,
                            "order {order:?}, sparse {sparse}, bit {bit}, row {row}, scalar {scalar}, index {index}: distance {distance}"
                        );
                    }
                }
            }
            assert_eq!(decoded, messages[bit as usize]);
            assert_eq!(
                decoded_product,
                messages[1].iter().map(|m| m * bit).collect::<Vec<_>>()
            );
        }

        let (_, recovery) = allocations::measure(|| evaluator.into_bootstrapper());
        assert_eq!(
            recovery.count, 0,
            "converted CBS retains ordinary workspace"
        );
    }
}
