use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::ggsw::NttGgsw;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::U64NttTable;
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
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
    for (order, distribution) in [
        (
            PbsOrder::BootstrapKeyswitch,
            SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
        ),
        (
            PbsOrder::BootstrapKeyswitch,
            SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
        ),
        (
            PbsOrder::KeyswitchBootstrap,
            SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
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
        let (client_key, server_key) = context
            .try_generate_keys(Some(cbs_config), &mut rng)
            .unwrap();
        let circuit_key = server_key.circuit_bootstrap_key().unwrap();
        let circuit_parameters = circuit_key.parameters();
        let main_secret =
            NttGlweSecretKey::from_coeff_secret_key(client_key.glwe_secret_key(), context.table());
        let glwe = context.parameters().accumulator_glwe();
        let mut accumulator_client = context.accumulator_client(&client_key).unwrap();
        let choices = [1u64, 3].map(|message| {
            let mut output = accumulator_client.allocate_ciphertext();
            let (_, allocation) = allocations::measure(|| {
                accumulator_client.encrypt_to(&[message; POLY_LENGTH], &mut output, &mut rng)
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
            .compile_lookup_table_fn(context.parameters().input_plaintext_codec(), |message| {
                message as u64
            })
            .unwrap();
        let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
        let output = context
            .evaluator(&server_key)
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

        if distribution.is_binary() {
            let sparse_server_key = KeyGenerator::new(&context)
                .try_generate_sparse_server_key(&client_key, 3, 4, &mut rng)
                .unwrap();
            assert!(matches!(
                context.circuit_bootstrap_evaluator(&sparse_server_key),
                Err(TfheEvaluationError::UnsupportedSparseBootstrapping)
            ));
        }
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
                &server_key,
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
                &server_key,
                &incompatible_parameters,
                circuit_key
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        // GLWE scheme switching binds output layout, so another output basis
        // with the same level count can reuse this circuit key.
        let alternate = CircuitBootstrapParameters::try_new(
            context.parameters(),
            ApproxSignedBasis::new(Some(MODULUS), 9, Some(levels)),
            circuit_parameters.trace().clone(),
            circuit_parameters.scheme_switch().clone(),
        )
        .unwrap();
        let (circuit_parameters, mut evaluator) = match order {
            PbsOrder::BootstrapKeyswitch => (
                circuit_parameters,
                context.circuit_bootstrap_evaluator(&server_key).unwrap(),
            ),
            PbsOrder::KeyswitchBootstrap => (
                &alternate,
                CircuitBootstrapEvaluator::try_from_parts(
                    &context,
                    &server_key,
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
        let mut selected = accumulator_client.allocate_ciphertext();
        let mut product = accumulator_client.allocate_ciphertext();
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
                accumulator_client.decrypt_to(&selected, &mut decoded);
                accumulator_client.decrypt_to(&product, &mut decoded_product);
            });
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
                            distance < (1 << 22),
                            "order {order:?}, levels {levels}, bit {bit}, row {row}, index {index}: distance {distance}"
                        );
                    }
                }
            }
            assert_eq!(decoded, vec![if bit == 0 { 1 } else { 3 }; POLY_LENGTH]);
            assert_eq!(decoded_product, vec![3 * bit; POLY_LENGTH]);
        }
    }
}

#[test]
fn circuit_parameters_check_capacity_layout_and_basis_domain() {
    use primus_tfhe_glwe_ntt::CircuitBootstrapParameterError as Error;
    let tfhe = parameters(
        PbsOrder::BootstrapKeyswitch,
        POLY_LENGTH as u64,
        SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
    );
    let config = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: 8,
            level_count: Some(2),
        },
        trace: DecompositionConfig {
            log_basis: 9,
            level_count: Some(3),
        },
        trace_noise_standard_deviation: 1.25,
        scheme_switch: DecompositionConfig {
            log_basis: 10,
            level_count: Some(4),
        },
        scheme_switch_noise_standard_deviation: 2.5,
    };
    let configured = CircuitBootstrapParameters::try_from_config(&tfhe, config).unwrap();
    assert_eq!(
        configured.output_size().glwe_size(),
        tfhe.accumulator_glwe().size()
    );
    assert_eq!(configured.trace().basis().log_basis(), 9);
    assert_eq!(configured.trace().basis().decompose_length(), 3);
    assert_eq!(configured.trace().noise_standard_deviation(), 1.25);
    assert_eq!(configured.scheme_switch().basis().log_basis(), 10);
    assert_eq!(configured.scheme_switch().basis().decompose_length(), 4);
    assert_eq!(configured.scheme_switch().noise_standard_deviation(), 2.5);
    for role in ["output", "trace", "scheme-switch"] {
        let mut invalid = config;
        match role {
            "output" => invalid.output.level_count = Some(0),
            "trace" => invalid.trace.level_count = Some(0),
            _ => invalid.scheme_switch.level_count = Some(0),
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
    let output = |levels| ApproxSignedBasis::new(Some(MODULUS), 8, Some(levels));
    let valid = CircuitBootstrapParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone())
        .unwrap();
    assert_eq!(
        valid.output_size().glwe_size(),
        tfhe.accumulator_glwe().size()
    );
    assert!(matches!(
        CircuitBootstrapParameters::try_new(&tfhe, output(3), trace.clone(), trace.clone()),
        Err(Error::OutputDecompositionTooLarge)
    ));
    for modulus in [None, Some(132_120_577)] {
        assert!(matches!(
            CircuitBootstrapParameters::try_new(
                &tfhe,
                ApproxSignedBasis::new(modulus, 8, Some(2)),
                trace.clone(),
                trace.clone(),
            ),
            Err(Error::OutputBasisModulusMismatch)
        ));
    }
    for (dimension, poly_length, modulus, expected) in [
        (
            2,
            POLY_LENGTH,
            MODULUS,
            Error::GlweLayoutMismatch { role: "trace" },
        ),
        (
            1,
            POLY_LENGTH * 2,
            MODULUS,
            Error::GlweLayoutMismatch { role: "trace" },
        ),
        (
            1,
            POLY_LENGTH,
            132_120_577,
            Error::CipherModulusMismatch { role: "trace" },
        ),
    ] {
        let foreign = GlweParameters::new(
            dimension,
            poly_length,
            4,
            BarrettModulus::new(modulus),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let result = CircuitBootstrapParameters::try_new(
            &tfhe,
            output(2),
            GgswParameters::with_glwe_params(&foreign, 8, Some(2)),
            trace.clone(),
        );
        assert_eq!(result.err(), Some(expected));
    }
}
