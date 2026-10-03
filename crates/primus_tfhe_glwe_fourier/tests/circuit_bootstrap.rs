//! Gadget-scale phases and actual CMux/external-product consumption;
//! parameter-constructor boundaries belong to the common family crate.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GlevParameters, SecretKeyDistr};
use primus_lattice::ggsw::{FourierGgsw, Ggsw};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::{LweCiphertext, LweParametersInner};
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_test_allocations as allocations;
use primus_tfhe::ProgrammableBootstrap as _;
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameters, ClientKey,
    DecompositionConfig, KeyGenerationError, KeyGenerator, PbsOrder, TfheConfig, TfheContext,
    TfheEvaluationError, TfheParameters,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const POLY_LENGTH: usize = 64;
const DIMENSION: usize = 2;

fn parameters(dimension: usize, poly_length: usize) -> TfheParameters<u64> {
    parameters_with_order_and_distribution(
        dimension,
        poly_length,
        PbsOrder::BootstrapKeyswitch,
        SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
    )
}

fn parameters_with_order_and_distribution(
    dimension: usize,
    poly_length: usize,
    order: PbsOrder,
    distribution: SecretKeyDistr,
) -> TfheParameters<u64> {
    // Retain enough precision below the smallest CBS output gadget scale.
    let decomposition = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: Some(DecompositionLevelCount::new(6)),
    };
    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParametersInner::new(
            LweDimension::new(4),
            NativeModulus::new(),
            distribution,
            0.7,
        ),
        accumulator_dimension: GlweDimension::new(dimension),
        poly_length,
        accumulator_secret_key_distr: SecretKeyDistr::UniformTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: decomposition,
        key_switching: decomposition,
        pbs_order: order,
    })
    .unwrap()
}

fn circuit_config() -> CircuitBootstrapConfig {
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(3)),
        },
        trace: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(7)),
        },
        trace_noise_standard_deviation: 0.7,
        scheme_switch: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: Some(DecompositionLevelCount::new(5)),
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

// Reuse one evaluator across controls, then consume its gadget ciphertexts.
fn circuit_bootstrap<Table: FftTable>(order: PbsOrder, distribution: SecretKeyDistr, sparse: bool) {
    let context = TfheContext::<_, Table>::from_parameters(parameters_with_order_and_distribution(
        DIMENSION,
        POLY_LENGTH,
        order,
        distribution,
    ));
    let input_codec = primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4342_534b_4559 ^ order as u64);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let server = if sparse {
        generator.try_generate_sparse_server_key(&client, 3, 4, Some(circuit_config()), &mut rng)
    } else {
        generator.try_generate_server_key(&client, Some(circuit_config()), &mut rng)
    }
    .unwrap();
    let key = server.circuit_bootstrap_key().unwrap();
    let parameters = key.parameters();
    // GLWE scheme switching binds the output layout, not its exact gadget basis.
    let alternate = CircuitBootstrapParameters::try_new(
        context.parameters(),
        ApproxSignedBasis::new(
            None,
            DecompositionBaseLog::new(if sparse { 8 } else { 9 }),
            Some(DecompositionLevelCount::new(3)),
        ),
        parameters.trace().clone(),
        parameters.scheme_switch().clone(),
    )
    .unwrap();
    let mut fft = context.new_fft_engine();
    let glwe = context.parameters().blind_rotation_ggsw();
    let messages = [1u64, 3].map(|offset| {
        (0..POLY_LENGTH)
            .map(|i| (i as u64 + offset) % 4)
            .collect::<Vec<_>>()
    });
    let mut accumulator_client = context
        .accumulator_client(
            &client,
            primus_encoding::ScaledCodec::new(
                input_codec.plaintext_modulus(),
                input_codec.ciphertext_modulus(),
            ),
        )
        .unwrap();
    let choices = messages.each_ref().map(|message| {
        let mut output = context.allocate_accumulator_ciphertext();
        let (_, allocation) =
            allocations::measure(|| accumulator_client.encrypt_to(message, &mut output, &mut rng));
        assert_eq!(
            allocation.count, 0,
            "accumulator encryption must reuse its workspace"
        );
        output
    });

    let encryptor = context.encryptor(&client, &input_codec).unwrap();
    // The same CBS-enabled server key also supports ordinary PBS.
    let identity = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap()
        .compile_fn(|message| message as u64)
        .unwrap();
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let mut output = context
        .evaluator(&server)
        .unwrap()
        .apply_lookup_table(input.as_view(), &identity);
    assert_eq!(
        context
            .decryptor(&client, &input_codec)
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
            .encryptor(&client, &other_codec)
            .unwrap()
            .encrypt_padded(1, &mut rng)
            .unwrap();
        let mut other = CircuitBootstrapEvaluator::try_from_parts(
            &context,
            &server,
            parameters,
            key,
            &other_codec,
        )
        .unwrap();
        let control = other.circuit_bootstrap(input.as_view());
        let mut selected = context.allocate_accumulator_ciphertext();
        other.cmux_to(&control, &choices[0], &choices[1], &mut selected);
        assert_eq!(accumulator_client.decrypt(&selected), messages[1]);
    }

    let (parameters, mut evaluator) = match order {
        PbsOrder::BootstrapKeyswitch => (parameters, {
            let mut standalone = context
                .circuit_bootstrap_evaluator(&server, &input_codec)
                .unwrap();
            assert!(standalone.bootstrapper_mut().is_none());
            // Exercise the missing-KS form before recovery fills that workspace.
            let mut control = standalone.allocate_output();
            let mut selected = context.allocate_accumulator_ciphertext();
            let mut decoded = vec![0; POLY_LENGTH];
            let (_, online) = allocations::measure(|| {
                standalone.circuit_bootstrap_to(input.as_view(), &mut control);
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
            CircuitBootstrapEvaluator::try_from_bootstrapper(pbs, &input_codec).unwrap()
        }),
        PbsOrder::KeyswitchBootstrap => (
            &alternate,
            CircuitBootstrapEvaluator::try_from_parts(
                &context,
                &server,
                &alternate,
                key,
                &input_codec,
            )
            .unwrap(),
        ),
    };
    assert_eq!(parameters.lookup_table_padded_output_count(), 4);

    let mut control = evaluator.allocate_output();
    let mut coefficients = Ggsw::new(vec![0u64; parameters.output_size().ggsw_len()]);
    let mut selected = context.allocate_accumulator_ciphertext();
    let mut product = context.allocate_accumulator_ciphertext();
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
            evaluator.circuit_bootstrap_to(input.as_view(), &mut control);
            evaluator.cmux_to(&control, &choices[0], &choices[1], &mut selected);
            evaluator.external_product_to(&control, &choices[1], &mut product);
            evaluator.bootstrapper_mut().unwrap().apply_lookup_table_to(
                input.as_view(),
                &identity,
                output.as_mut_view(),
            );
            accumulator_client.decrypt_to(&selected, &mut decoded);
            accumulator_client.decrypt_to(&product, &mut decoded_product);
        });
        assert_eq!(
            context
                .decryptor(&client, &input_codec)
                .unwrap()
                .decrypt(output.as_view())
                .unwrap(),
            bit
        );
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
                        "order={order:?}, distribution={distribution:?}, sparse={sparse}, bit={bit}, row={row}, scale={scalar}, coefficient={index}"
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

    let (_, recovery) = allocations::measure(|| evaluator.into_bootstrapper());
    assert_eq!(
        recovery.count, 0,
        "converted CBS retains ordinary workspace"
    );
}

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        for distribution in [
            SecretKeyDistr::fixed_hamming_weight_binary(4, 2),
            SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
        ] {
            for sparse in [false, true] {
                if sparse && !distribution.is_binary() {
                    continue;
                }
                circuit_bootstrap::<RustFftTable>(order, distribution, sparse);
                circuit_bootstrap::<TfheFftTable>(order, distribution, sparse);
            }
        }
    }
}

#[test]
fn evaluator_rejects_resource_mismatches_and_checks_shapes_before_writes() {
    use TfheEvaluationError as Error;
    let context = TfheContext::try_new(
        parameters(DIMENSION, POLY_LENGTH),
        RustFftTable::new(PolyLength::new(POLY_LENGTH)),
    )
    .unwrap();
    let input_codec = primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(42);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let parameters = circuit_parameters(context.parameters());
    let mut generator = KeyGenerator::new(&context);
    let key = generator
        .try_generate_circuit_bootstrap_key(&client, parameters.clone(), &mut rng)
        .unwrap();
    // CBS leaves a different gadget layout; the next PBS generation must resize it.
    let server = generator
        .try_generate_sparse_server_key(&client, 3, 4, None, &mut rng)
        .unwrap();
    // Keep level counts equal for basis mismatches, so layout checks cannot mask them.
    for (output, trace, scheme_switch) in [
        (
            ApproxSignedBasis::new(
                None,
                DecompositionBaseLog::new(8),
                Some(DecompositionLevelCount::new(2)),
            ),
            parameters.trace().clone(),
            parameters.scheme_switch().clone(),
        ),
        (
            parameters.output_basis().clone(),
            GlevParameters::with_glwe_params(
                &primus_glwe::GlweParameters::try_from_glev(
                    context.parameters().blind_rotation_ggsw(),
                    primus_encoding::ScaledCodec::new(4, NativeModulus::new()),
                )
                .unwrap(),
                DecompositionBaseLog::new(7),
                Some(DecompositionLevelCount::new(7)),
            ),
            parameters.scheme_switch().clone(),
        ),
        (
            parameters.output_basis().clone(),
            parameters.trace().clone(),
            GlevParameters::with_glwe_params(
                &primus_glwe::GlweParameters::try_from_glev(
                    context.parameters().blind_rotation_ggsw(),
                    primus_encoding::ScaledCodec::new(4, NativeModulus::new()),
                )
                .unwrap(),
                DecompositionBaseLog::new(9),
                Some(DecompositionLevelCount::new(5)),
            ),
        ),
    ] {
        let foreign =
            CircuitBootstrapParameters::try_new(context.parameters(), output, trace, scheme_switch)
                .unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_from_parts(
                &context,
                &server,
                &foreign,
                &key,
                &input_codec
            ),
            Err(Error::IncompatibleCircuitBootstrapKey)
        ));
    }
    let foreign_tfhe = parameters_with_order_and_distribution(
        DIMENSION,
        POLY_LENGTH,
        PbsOrder::BootstrapKeyswitch,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
    );
    let foreign_context = TfheContext::try_new(
        foreign_tfhe,
        RustFftTable::new(PolyLength::new(POLY_LENGTH)),
    )
    .unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_from_parts(
            &foreign_context,
            &server,
            &parameters,
            &key,
            &input_codec
        ),
        Err(Error::IncompatibleServerKey)
    ));
    // Message t belongs to the program, so both encodings bind the same CBS key.
    let other_codec = primus_encoding::RoundedCodec::new(8, context.parameters().cipher_modulus());
    assert!(
        CircuitBootstrapEvaluator::try_from_parts(
            &context,
            &server,
            &parameters,
            &key,
            &other_codec,
        )
        .is_ok()
    );

    let mut evaluator = CircuitBootstrapEvaluator::try_from_parts(
        &context,
        &server,
        &parameters,
        &key,
        &input_codec,
    )
    .unwrap();
    let input_dimension = context.parameters().external_lwe_dimension().get();
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
                || evaluator.circuit_bootstrap_to(input.as_view(), &mut output)
            ))
            .is_err()
        );
        assert!(output.as_ref().iter().all(|&value| value == marker));
    }
}

#[test]
fn incompatible_parameters_and_client_keys_are_rejected_before_sampling() {
    let context = TfheContext::try_new(
        parameters(DIMENSION, POLY_LENGTH),
        RustFftTable::new(PolyLength::new(POLY_LENGTH)),
    )
    .unwrap();

    let mut rng = StdRng::seed_from_u64(42);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    for (dimension, poly_length) in [(DIMENSION + 1, POLY_LENGTH), (DIMENSION, POLY_LENGTH * 2)] {
        let foreign = circuit_parameters(&parameters(dimension, poly_length));
        let mut rng = StdRng::seed_from_u64(43);
        let mut untouched_rng = StdRng::seed_from_u64(43);
        assert!(matches!(
            context.try_generate_circuit_bootstrap_key(&client, foreign, &mut rng),
            Err(KeyGenerationError::IncompatibleCircuitBootstrapParameters)
        ));
        assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
    }
    let mut invalid = circuit_config();
    invalid.output.level_count = Some(DecompositionLevelCount::new(usize::MAX));
    let mut rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(matches!(
        context.try_generate_keys(Some(invalid), &mut rng),
        Err(KeyGenerationError::CircuitBootstrapParameters(_))
    ));
    assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
    let mut rng = StdRng::seed_from_u64(44);
    let mut untouched_rng = StdRng::seed_from_u64(44);
    assert!(matches!(
        KeyGenerator::new(&context).try_generate_sparse_server_key(
            &client,
            3,
            4,
            Some(invalid),
            &mut rng
        ),
        Err(KeyGenerationError::CircuitBootstrapParameters(_))
    ));
    assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
    let foreign_client = ClientKey::generate(&parameters(DIMENSION + 1, POLY_LENGTH), &mut rng);
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
