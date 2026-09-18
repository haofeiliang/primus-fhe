use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GlevParameters, GlweParameters, SecretKeyDistr};
use primus_lattice::ggsw::{FourierGgsw, Ggsw};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_test_allocations as allocations;
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameterError,
    CircuitBootstrapParameters, ClientKey, DecompositionConfig, KeyGenerationError, KeyGenerator,
    PbsOrder, TfheContext, TfheEvaluationError, TfheParameters,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const POLY_LENGTH: usize = 128;
const DIMENSION: usize = 2;

fn parameters(dimension: usize, poly_length: usize, plaintext_modulus: u64) -> TfheParameters<u64> {
    parameters_with_order_and_distribution(
        dimension,
        poly_length,
        plaintext_modulus,
        PbsOrder::BootstrapKeyswitch,
        SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
    )
}

fn parameters_with_order_and_distribution(
    dimension: usize,
    poly_length: usize,
    plaintext_modulus: u64,
    order: PbsOrder,
    distribution: SecretKeyDistr,
) -> TfheParameters<u64> {
    TfheParameters::try_new(
        LweParameters::new(
            4,
            plaintext_modulus,
            NativeModulus::new(),
            distribution,
            0.7,
        ),
        GlweParameters::new(
            dimension,
            poly_length,
            plaintext_modulus,
            NativeModulus::new(),
            SecretKeyDistr::UniformTernary,
            0.7,
        ),
        // Retain enough precision below the smallest CBS output gadget scale.
        ApproxSignedBasis::new(None, 8, Some(6)),
        ApproxSignedBasis::new(None, 8, Some(6)),
        order,
    )
    .unwrap()
}

fn circuit_config() -> CircuitBootstrapConfig {
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: 8,
            level_count: Some(3),
        },
        trace: DecompositionConfig {
            log_basis: 8,
            level_count: Some(7),
        },
        trace_noise_standard_deviation: 0.7,
        scheme_switch: DecompositionConfig {
            log_basis: 10,
            level_count: Some(5),
        },
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

fn circuit_parameters(tfhe: &TfheParameters<u64>) -> CircuitBootstrapParameters<u64> {
    CircuitBootstrapParameters::try_from_config(tfhe, circuit_config()).unwrap()
}

// Exact native-ring phase, independent of FFT and sample extraction.
fn phase(ciphertext: &[u64], secret: &[i64]) -> Vec<u64> {
    let (mask, body) = ciphertext.split_at(DIMENSION * POLY_LENGTH);
    let mut phase = body.to_vec();
    for (mask, secret) in mask
        .as_chunks::<POLY_LENGTH>()
        .0
        .iter()
        .zip(secret.as_chunks::<POLY_LENGTH>().0)
    {
        for (i, &a) in mask.iter().enumerate() {
            for (j, &s) in secret.iter().enumerate() {
                let product = a.wrapping_mul(s as u64);
                let coefficient = &mut phase[(i + j) % POLY_LENGTH];
                *coefficient = if i + j < POLY_LENGTH {
                    coefficient.wrapping_sub(product)
                } else {
                    coefficient.wrapping_add(product)
                };
            }
        }
    }
    phase
}

fn circuit_bootstrap<Table: FftTable>(order: PbsOrder, distribution: SecretKeyDistr) {
    let context = TfheContext::<_, Table>::try_from_parameters(
        parameters_with_order_and_distribution(DIMENSION, POLY_LENGTH, 4, order, distribution),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(0x4342_534b_4559 ^ order as u64);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let server = generator
        .try_generate_server_key(&client, Some(circuit_config()), &mut rng)
        .unwrap();
    let key = server.circuit_bootstrap_key().unwrap();
    let parameters = key.parameters();
    // GLWE scheme switching binds the output layout, not its exact gadget basis.
    let alternate = CircuitBootstrapParameters::try_new(
        context.parameters(),
        ApproxSignedBasis::new(None, 9, Some(3)),
        parameters.trace().clone(),
        parameters.scheme_switch().clone(),
    )
    .unwrap();
    let (parameters, mut evaluator) = match order {
        PbsOrder::BootstrapKeyswitch => (
            parameters,
            context.circuit_bootstrap_evaluator(&server).unwrap(),
        ),
        PbsOrder::KeyswitchBootstrap => (
            &alternate,
            CircuitBootstrapEvaluator::try_from_parts(&context, &server, &alternate, key).unwrap(),
        ),
    };
    assert_eq!(parameters.lookup_table_padded_output_count(), 4);

    let mut fft = context.new_fft_engine();
    let glwe = context.parameters().accumulator_glwe();
    let messages = [1u64, 3].map(|offset| {
        (0..POLY_LENGTH)
            .map(|i| (i as u64 + offset) % 4)
            .collect::<Vec<_>>()
    });
    let mut accumulator_client = context.accumulator_client(&client).unwrap();
    let choices = messages.each_ref().map(|message| {
        let mut output = accumulator_client.allocate_ciphertext();
        let (_, allocation) =
            allocations::measure(|| accumulator_client.encrypt_to(message, &mut output, &mut rng));
        assert_eq!(
            allocation.count, 0,
            "accumulator encryption must reuse its workspace"
        );
        output
    });

    let encryptor = context.encryptor(&client).unwrap();
    // The same CBS-enabled server key also supports ordinary PBS.
    let identity = context
        .parameters()
        .compile_lookup_table_fn(context.parameters().input_plaintext_codec(), |message| {
            message as u64
        })
        .unwrap();
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let output = context
        .evaluator(&server)
        .unwrap()
        .apply_lookup_table(&input, &identity);
    assert_eq!(
        context
            .decryptor(&client)
            .unwrap()
            .decrypt(&output)
            .unwrap(),
        1
    );

    let mut control = evaluator.allocate_output();
    let mut coefficients = Ggsw::new(vec![0u64; parameters.output_size().ggsw_len()]);
    let mut selected = accumulator_client.allocate_ciphertext();
    let mut product = accumulator_client.allocate_ciphertext();
    let mut decoded = vec![0; POLY_LENGTH];
    let mut decoded_product = vec![0; POLY_LENGTH];
    // Raw ciphertext containers carry no layout; the bound entry must reject
    // a short control before touching a reused output.
    selected.as_mut().fill(7);
    let short_control = FourierGgsw::new(&control.as_ref()[..control.as_ref().len() - 1]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.cmux_to(&short_control, &choices[0], &choices[1], &mut selected);
        }))
        .is_err()
    );
    assert!(selected.as_ref().iter().all(|&value| value == 7));
    // Functional fixture bound, with a factor-four margin to the smallest scale.
    let tolerance = parameters.output_basis().scalar_iter().min().unwrap() / 4;
    // Reuse the output for a zero control after a nonzero control, without clearing it.
    for bit in [1u64, 0] {
        let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
        let (_, allocation) = allocations::measure(|| {
            evaluator.circuit_bootstrap_to(&input, &mut control);
            evaluator.cmux_to(&control, &choices[0], &choices[1], &mut selected);
            evaluator.external_product_to(&control, &choices[1], &mut product);
            accumulator_client.decrypt_to(&selected, &mut decoded);
            accumulator_client.decrypt_to(&product, &mut decoded_product);
        });
        assert_eq!(
            allocation.count, 0,
            "CBS must reuse workspace from the first call"
        );
        control.write_torus_form(&mut coefficients, &mut fft);
        for (row, levels) in coefficients
            .as_ref()
            .chunks_exact(parameters.output_size().glev_len())
            .enumerate()
        {
            for (scalar, ciphertext) in parameters
                .output_basis()
                .scalar_iter()
                .zip(levels.chunks_exact(glwe.glwe_len()))
            {
                for (index, actual) in phase(ciphertext, client.glwe_secret_key().as_slice())
                    .into_iter()
                    .enumerate()
                {
                    let coefficient = if row == DIMENSION {
                        u64::from(index == 0)
                    } else {
                        (client.glwe_secret_key().as_slice()[row * POLY_LENGTH + index] as u64)
                            .wrapping_neg()
                    };
                    let expected = coefficient.wrapping_mul(scalar).wrapping_mul(bit);
                    let error = actual.wrapping_sub(expected);
                    assert!(
                        error.min(error.wrapping_neg()) < tolerance,
                        "order={order:?}, distribution={distribution:?}, bit={bit}, row={row}, scale={scalar}, coefficient={index}"
                    );
                }
            }
        }
        assert_eq!(decoded, messages[bit as usize]);
        assert_eq!(
            decoded_product,
            messages[1]
                .iter()
                .map(|&value| value * bit)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        for distribution in [
            SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
            SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
        ] {
            circuit_bootstrap::<RustFftTable>(order, distribution);
            circuit_bootstrap::<TfheFftTable>(order, distribution);
        }
    }
}

#[test]
fn evaluator_rejects_resource_mismatches_and_checks_shapes_before_writes() {
    use TfheEvaluationError as Error;
    let context = TfheContext::try_new(
        parameters(DIMENSION, POLY_LENGTH, 4),
        RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let parameters = circuit_parameters(context.parameters());
    let mut generator = KeyGenerator::new(&context);
    let key = generator
        .try_generate_circuit_bootstrap_key(&client, parameters.clone(), &mut rng)
        .unwrap();
    // CBS leaves a different gadget layout; the next PBS generation must resize it.
    let server = generator
        .try_generate_server_key(&client, None, &mut rng)
        .unwrap();
    // Keep level counts equal for basis mismatches, so layout checks cannot mask them.
    for (output, trace, scheme_switch) in [
        (
            ApproxSignedBasis::new(None, 8, Some(2)),
            parameters.trace().clone(),
            parameters.scheme_switch().clone(),
        ),
        (
            parameters.output_basis().clone(),
            GlevParameters::with_glwe_params(context.parameters().accumulator_glwe(), 7, Some(7)),
            parameters.scheme_switch().clone(),
        ),
        (
            parameters.output_basis().clone(),
            parameters.trace().clone(),
            GlevParameters::with_glwe_params(context.parameters().accumulator_glwe(), 9, Some(5)),
        ),
    ] {
        let foreign =
            CircuitBootstrapParameters::try_new(context.parameters(), output, trace, scheme_switch)
                .unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_from_parts(&context, &server, &foreign, &key),
            Err(Error::IncompatibleCircuitBootstrapKey)
        ));
    }
    let foreign_tfhe = parameters_with_order_and_distribution(
        DIMENSION,
        POLY_LENGTH,
        4,
        PbsOrder::BootstrapKeyswitch,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
    );
    let foreign_context = TfheContext::try_new(
        foreign_tfhe,
        RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_from_parts(&foreign_context, &server, &parameters, &key),
        Err(Error::IncompatibleServerKey)
    ));
    let foreign_parameters = circuit_parameters(&parameters_with_order_and_distribution(
        DIMENSION,
        POLY_LENGTH,
        8,
        PbsOrder::BootstrapKeyswitch,
        SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
    ));
    assert!(matches!(
        CircuitBootstrapEvaluator::try_from_parts(&context, &server, &foreign_parameters, &key),
        Err(Error::IncompatibleCircuitBootstrapParameters)
    ));

    let mut evaluator =
        CircuitBootstrapEvaluator::try_from_parts(&context, &server, &parameters, &key).unwrap();
    let input_dimension = context.parameters().external_lwe_dimension();
    let output_len = parameters.output_size().fourier_ggsw_len();
    for (dimension, length) in [
        (input_dimension - 1, output_len),
        (input_dimension, output_len - 1),
    ] {
        let input = LweCiphertext::zero(dimension);
        let marker = Complex64::new(7.0, -3.0);
        let mut output = FourierGgsw::new(vec![marker; length]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || evaluator.circuit_bootstrap_to(&input, &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == marker));
    }
}

#[test]
fn circuit_parameters_check_native_basis_layout_and_padded_capacity() {
    use CircuitBootstrapParameterError as Error;
    let tfhe = parameters(DIMENSION, POLY_LENGTH, POLY_LENGTH as u64);
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
    let make =
        |basis| CircuitBootstrapParameters::try_new(&tfhe, basis, trace.clone(), trace.clone());
    assert!(make(ApproxSignedBasis::new(None, 8, Some(2))).is_ok());
    assert_eq!(
        make(ApproxSignedBasis::new(None, 8, Some(3))).err(),
        Some(Error::OutputDecompositionTooLarge)
    );
    assert_eq!(
        make(ApproxSignedBasis::new(Some(1 << 63), 8, Some(2))).err(),
        Some(Error::OutputBasisModulusMismatch)
    );
    for (dimension, poly_length) in [(DIMENSION + 1, POLY_LENGTH), (DIMENSION, POLY_LENGTH * 2)] {
        let foreign = parameters(dimension, poly_length, 4);
        for (role, trace, scheme_switch) in [
            (
                "trace",
                foreign.blind_rotation_ggsw().clone(),
                trace.clone(),
            ),
            (
                "scheme-switch",
                trace.clone(),
                foreign.blind_rotation_ggsw().clone(),
            ),
        ] {
            assert_eq!(
                CircuitBootstrapParameters::try_new(
                    &tfhe,
                    ApproxSignedBasis::new(None, 8, Some(2)),
                    trace,
                    scheme_switch
                )
                .err(),
                Some(Error::GlweLayoutMismatch { role })
            );
        }
    }
}

#[test]
fn incompatible_parameters_and_client_keys_are_rejected_before_sampling() {
    let context = TfheContext::try_new(
        parameters(DIMENSION, POLY_LENGTH, 4),
        RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    for (dimension, poly_length, plaintext_modulus) in [
        (DIMENSION + 1, POLY_LENGTH, 4),
        (DIMENSION, POLY_LENGTH * 2, 4),
        (DIMENSION, POLY_LENGTH, 8),
    ] {
        let foreign = circuit_parameters(&parameters(dimension, poly_length, plaintext_modulus));
        let mut rng = StdRng::seed_from_u64(43);
        let mut untouched_rng = StdRng::seed_from_u64(43);
        assert!(matches!(
            context.try_generate_circuit_bootstrap_key(&client, foreign, &mut rng),
            Err(KeyGenerationError::IncompatibleCircuitBootstrapParameters)
        ));
        assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
    }
    let mut invalid = circuit_config();
    invalid.output.level_count = Some(0);
    let mut rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(matches!(
        context.try_generate_keys(Some(invalid), &mut rng),
        Err(KeyGenerationError::CircuitBootstrapParameters(_))
    ));
    assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
    let foreign_client = ClientKey::generate(&parameters(DIMENSION + 1, POLY_LENGTH, 4), &mut rng);
    let mut rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(matches!(
        context.try_generate_circuit_bootstrap_key(
            &foreign_client,
            circuit_parameters(context.parameters()),
            &mut rng
        ),
        Err(KeyGenerationError::ClientKey(_))
    ));
    assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
}
