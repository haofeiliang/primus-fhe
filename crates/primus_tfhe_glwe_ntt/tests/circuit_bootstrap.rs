//! Gadget-scale phases and actual CMux/external-product consumption;
//! parameter-constructor boundaries belong to the common family crate.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_glwe::{GgswParameters, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::ggsw::NttGgsw;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::{LweCiphertext, LweEncryptionParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::U64NttTable;
use primus_poly::PolyLength;
use primus_poly::Polynomial;
use primus_test_allocations as allocations;
use primus_tfhe_glwe_ntt::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapEvaluator,
    CircuitBootstrapParameters, DecompositionConfig, KeyGenerator, PbsOrder, TfheConfig,
    TfheContext, TfheEvaluationError, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const POLY_LENGTH: usize = 64;
const MODULUS: u64 = 1_125_899_906_826_241;

fn parameters(order: PbsOrder, distribution: SecretKeyDistr) -> TfheParameters<u64> {
    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweEncryptionParameters::new(
            LweDimension::new(4),
            BarrettModulus::new(MODULUS),
            distribution,
            0.7,
        ),
        accumulator_dimension: GlweDimension::new(1),
        poly_length: PolyLength::new(POLY_LENGTH),
        accumulator_secret_key_distr: SecretKeyDistr::UniformBinary,
        accumulator_noise_standard_deviation: 0.7,
        // Full decomposition keeps phase error below the third output level.
        blind_rotation: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(4)),
        },
        key_switching_noise_standard_deviation: 0.7,
        pbs_order: order,
    })
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
        let tfhe = parameters(order, distribution);
        let modulus = BarrettModulus::new(MODULUS);
        let context = TfheContext::<_, U64NttTable>::try_from_parameters(tfhe).unwrap();
        let input_codec =
            primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
        let mut rng = StdRng::seed_from_u64(0x0050_4154_4348_4544 ^ order as u64);
        // Three gadget levels exercise multiple scales and an internal padding slot.
        let levels = 3;
        let cbs_config = CircuitBootstrapConfig {
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(levels)),
            },
            trace: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: None,
            },
            trace_noise_standard_deviation: 0.7,
            scheme_switch: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
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
                .try_generate_server_key(
                    &client_key,
                    BlindRotationConfig::Sparse {
                        copy_count: 3,
                        bucket_count: 4,
                    },
                    config,
                    &mut rng,
                )
                .unwrap()
        });
        let server_key = sparse_server_key.as_ref().unwrap_or(&classic_server_key);
        let circuit_key = server_key
            .circuit_bootstrap_key()
            .unwrap_or_else(|| classic_server_key.circuit_bootstrap_key().unwrap());
        let circuit_parameters = circuit_key.parameters();
        let mut resources = context
            .bootstrap_resources_from_server_key(server_key)
            .unwrap();
        let main_secret =
            NttGlweSecretKey::from_coeff_secret_key(client_key.glwe_secret_key(), context.table());
        let glwe = context.parameters().blind_rotation_ggsw();
        let mut accumulator_client = context
            .accumulator_client(
                client_key.glwe_secret_key(),
                primus_encoding::ScaledCodec::new(
                    input_codec.plaintext_modulus(),
                    input_codec.ciphertext_modulus(),
                ),
            )
            .unwrap();
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

        let encryptor = context
            .encryptor(client_key.external_lwe_secret_key(), &input_codec)
            .unwrap();
        // The same CBS-enabled server key also supports ordinary PBS.
        let identity = context
            .parameters()
            .lookup_table_compiler(&input_codec)
            .unwrap()
            .compile_fn(|message| message as u64)
            .unwrap();
        let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
        let mut output = context
            .evaluator(server_key)
            .unwrap()
            .apply_lookup_table(input.as_view(), &identity);
        assert_eq!(
            context
                .decryptor(client_key.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .decrypt(output.as_view())
                .unwrap(),
            1
        );

        // Compile another input encoding with the same CBS keys and consume its
        // gadget output. Accumulator messages keep their independently chosen t=4.
        if !sparse && order == PbsOrder::BootstrapKeyswitch {
            let other_codec =
                primus_encoding::RoundedCodec::new(8, context.parameters().cipher_modulus());
            let input = context
                .encryptor(client_key.external_lwe_secret_key(), &other_codec)
                .unwrap()
                .encrypt_padded(1, &mut rng)
                .unwrap();
            let mut other =
                CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &other_codec).unwrap();
            let control = other.circuit_bootstrap(input.as_view(), &mut resources);
            let mut selected = context.allocate_accumulator_ciphertext();
            other.cmux_to(
                &control,
                &choices[0],
                &choices[1],
                &mut selected,
                &mut resources,
            );
            assert_eq!(accumulator_client.decrypt(&selected), messages[1]);
        }

        let other_context = TfheContext::<_, U64NttTable>::try_from_parameters(parameters(
            order,
            SecretKeyDistr::UniformBinary,
        ))
        .unwrap();
        assert!(matches!(
            other_context.bootstrap_resources_from_server_key(server_key),
            Err(TfheEvaluationError::IncompatibleBlindRotationKey)
        ));
        let incompatible_trace = GgswParameters::with_glwe_params(
            &primus_glwe::GlweParameters::try_from_glev(
                context.parameters().blind_rotation_ggsw(),
                primus_encoding::ScaledCodec::new(4, modulus),
            )
            .unwrap(),
            DecompositionBaseLog::new(9),
            None,
        );
        let incompatible_parameters = CircuitBootstrapParameters::try_new(
            context.parameters(),
            circuit_parameters.output_basis().clone(),
            incompatible_trace,
            circuit_parameters.scheme_switch().clone(),
        )
        .unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_with_parameters(
                &resources,
                &incompatible_parameters,
                circuit_key,
                &input_codec
            ),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
        // GLWE scheme switching binds output layout, so another output basis
        // with the same level count can reuse this circuit key.
        let alternate = CircuitBootstrapParameters::try_new(
            context.parameters(),
            ApproxSignedBasis::new(
                Some(MODULUS),
                DecompositionBaseLog::new(if sparse { 8 } else { 9 }),
                Some(DecompositionLevelCount::new(levels)),
            ),
            circuit_parameters.trace().clone(),
            circuit_parameters.scheme_switch().clone(),
        )
        .unwrap();
        // Missing input KS must fail at binding, for classic and sparse alike.
        if order == PbsOrder::KeyswitchBootstrap {
            let (result, allocation) = allocations::measure(|| {
                context.bootstrap_resources(server_key.blind_rotation_key(), None)
            });
            assert!(matches!(
                result,
                Err(TfheEvaluationError::MissingGlweKeySwitchingKey)
            ));
            assert_eq!(allocation.count, 0);
        }

        let circuit_parameters = if order == PbsOrder::KeyswitchBootstrap {
            &alternate
        } else {
            circuit_parameters
        };
        let mut evaluator = if order == PbsOrder::KeyswitchBootstrap {
            CircuitBootstrapEvaluator::try_with_parameters(
                &resources,
                circuit_parameters,
                circuit_key,
                &input_codec,
            )
        } else {
            CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)
        }
        .unwrap();
        // Standalone CBS has exactly the input resources required by its order.
        let mut control = evaluator.allocate_output();
        let mut selected = context.allocate_accumulator_ciphertext();
        let (_, online) = allocations::measure(|| {
            evaluator.circuit_bootstrap_to(input.as_view(), &mut control, &mut resources);
            evaluator.cmux_to(
                &control,
                &choices[0],
                &choices[1],
                &mut selected,
                &mut resources,
            );
        });
        assert_eq!(online.count, 0);
        assert_eq!(accumulator_client.decrypt(&selected), messages[1]);
        // Moving common resources preserves the prepared CBS. Only BR→KS needs
        // to allocate a missing return stage; KS→BR already owns the input KS.
        let (mut pbs, assembly) = allocations::measure(|| {
            primus_tfhe_glwe_ntt::Evaluator::try_from_resources(
                resources,
                server_key.glwe_key_switching_key(),
            )
            .unwrap()
        });
        assert_eq!(assembly.count == 0, order == PbsOrder::KeyswitchBootstrap);
        assert_eq!(
            circuit_parameters.lookup_table_padded_output_count(),
            levels.next_power_of_two()
        );
        let mut control = evaluator.allocate_output();
        let mut selected = context.allocate_accumulator_ciphertext();
        // Equal parameters do not identify a transform context. Reject a foreign
        // resource owner before touching the caller's output.
        let foreign_context =
            TfheContext::<_, U64NttTable>::try_from_parameters(context.parameters().clone())
                .unwrap();
        let mut foreign_resources = foreign_context
            .bootstrap_resources_from_server_key(server_key)
            .unwrap();
        control.as_mut().fill(7);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                evaluator.circuit_bootstrap_to(
                    input.as_view(),
                    &mut control,
                    &mut foreign_resources,
                );
            }))
            .is_err()
        );
        assert!(control.as_ref().iter().all(|&coefficient| coefficient == 7));
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
                            evaluator.circuit_bootstrap_to(
                                bad_input.as_view(),
                                &mut bad_output,
                                pbs.bootstrap_resources_mut(),
                            );
                        }))
                        .is_err()
                    );
                    assert!(bad_output.as_ref().iter().all(|&value| value == 7));
                }
            }
            let (_, allocation) = allocations::measure(|| {
                evaluator.circuit_bootstrap_to(
                    input.as_view(),
                    &mut control,
                    pbs.bootstrap_resources_mut(),
                );
                evaluator.cmux_to(
                    &control,
                    &choices[0],
                    &choices[1],
                    &mut selected,
                    pbs.bootstrap_resources_mut(),
                );
                evaluator.external_product_to(
                    &control,
                    &choices[1],
                    &mut product,
                    pbs.bootstrap_resources_mut(),
                );
                pbs.apply_lookup_table_to(input.as_view(), &identity, output.as_mut_view());
                accumulator_client.decrypt_to(&selected, &mut decoded);
                accumulator_client.decrypt_to(&product, &mut decoded_product);
            });
            assert_eq!(
                context
                    .decryptor(client_key.external_lwe_secret_key(), &input_codec)
                    .unwrap()
                    .decrypt(output.as_view())
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

        // Rebinding another KS from the same secrets must retain buffers and
        // use the replacement in the active stage of either PBS order.
        let replacement = KeyGenerator::new(&context)
            .try_generate_glwe_key_switching_key(&client_key, &mut rng)
            .unwrap();
        let (_, rebind) =
            allocations::measure(|| pbs.try_rebind_key_switching_key(&replacement).unwrap());
        assert_eq!(
            rebind.count, 0,
            "compatible KS rebind retains ordinary workspace"
        );
        pbs.apply_lookup_table_to(input.as_view(), &identity, output.as_mut_view());
        assert_eq!(
            context
                .decryptor(client_key.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .decrypt(output.as_view())
                .unwrap(),
            1
        );
    }
}
