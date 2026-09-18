#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{
    FourierGlweEncryptContext, FourierGlweSecretKey, GlevParameters, GlweParameters, SecretKeyDistr,
};
use primus_lattice::{
    context::FourierGlweExternalProductContext,
    ggsw::{FourierGgsw, Ggsw},
    glwe::Glwe,
};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluationError, CircuitBootstrapKeyError,
    CircuitBootstrapParameterError, CircuitBootstrapParameters, ClientKey, DecompositionConfig,
    KeyGenerator, PbsOrder, TfheContext, TfheParameters,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

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

fn circuit_parameters(tfhe: &TfheParameters<u64>) -> CircuitBootstrapParameters<u64> {
    CircuitBootstrapParameters::try_from_config(
        tfhe,
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
        },
    )
    .unwrap()
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
    let parameters = circuit_parameters(context.parameters());
    let mut rng = StdRng::seed_from_u64(0x4342_534b_4559 ^ order as u64);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let mut generator = KeyGenerator::new(&context);
    let key = generator
        .try_generate_circuit_bootstrap_key(&client, &parameters, &mut rng)
        .unwrap();
    // CBS leaves a different gadget layout in the reusable generator.
    let server = generator
        .try_generate_server_key(&client, &mut rng)
        .unwrap();
    // GLWE scheme switching binds the output layout, not its exact gadget basis.
    let parameters = CircuitBootstrapParameters::try_new(
        context.parameters(),
        ApproxSignedBasis::new(None, 9, Some(3)),
        parameters.trace().clone(),
        parameters.scheme_switch().clone(),
    )
    .unwrap();
    let mut evaluator = context
        .circuit_bootstrap_evaluator(&server, &parameters, &key)
        .unwrap();
    assert_eq!(parameters.lookup_table_padded_output_count(), 4);

    let mut fft = context.new_fft_engine();
    let secret = FourierGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), &mut fft);
    let glwe = context.parameters().accumulator_glwe();
    let mut encrypt = FourierGlweEncryptContext::new(POLY_LENGTH);
    let messages = [1u64, 3].map(|offset| {
        (0..POLY_LENGTH)
            .map(|i| (i as u64 + offset) % 4)
            .collect::<Vec<_>>()
    });
    let choices = messages.each_ref().map(|message| {
        let encrypted = secret.encrypt(
            &Polynomial::new(message.as_slice()),
            glwe,
            &mut fft,
            &mut rng,
            &mut encrypt,
        );
        let mut output = Glwe::<Vec<u64>>::zero(glwe.glwe_len());
        encrypted.write_torus_form(&mut output, &mut fft);
        output
    });
    let encryptor = context.encryptor(&client).unwrap();
    let mut control = FourierGgsw::<Vec<_>>::zero(parameters.output_size().fourier_ggsw_len());
    let mut coefficients = Ggsw::new(vec![0u64; parameters.output_size().ggsw_len()]);
    let mut selected = Glwe::new(vec![0u64; glwe.glwe_len()]);
    let mut external_product = FourierGlweExternalProductContext::new(parameters.output_size());
    // Functional fixture bound, with a factor-four margin to the smallest scale.
    let tolerance = parameters.output_basis().scalar_iter().min().unwrap() / 4;
    // Reuse the output for a zero control after a nonzero control, without clearing it.
    for bit in [1u64, 0] {
        let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
        let (_, allocation) =
            allocations::measure(|| evaluator.circuit_bootstrap_to(&input, &mut control));
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
        control.cmux_to(
            &choices[0],
            &choices[1],
            &mut selected,
            parameters.output_basis(),
            &mut fft,
            &mut external_product,
        );
        let mut decoded = phase(selected.as_ref(), client.glwe_secret_key().as_slice());
        glwe.plaintext_codec().decode_slice_assign(&mut decoded);
        assert_eq!(
            decoded, messages[bit as usize],
            "order={order:?}, distribution={distribution:?}, bit={bit}"
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
    use CircuitBootstrapEvaluationError as Error;
    let context = TfheContext::try_new(
        parameters(DIMENSION, POLY_LENGTH, 4),
        RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (client, server) = context.generate_keys(&mut rng).unwrap();
    let parameters = circuit_parameters(context.parameters());
    let key = context
        .generate_circuit_bootstrap_key(&client, &parameters, &mut rng)
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
            context.circuit_bootstrap_evaluator(&server, &foreign, &key),
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
        foreign_context.circuit_bootstrap_evaluator(&server, &parameters, &key),
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
        context.circuit_bootstrap_evaluator(&server, &foreign_parameters, &key),
        Err(Error::IncompatibleParameters)
    ));

    let mut evaluator = context
        .circuit_bootstrap_evaluator(&server, &parameters, &key)
        .unwrap();
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
            context.generate_circuit_bootstrap_key(&client, &foreign, &mut rng),
            Err(CircuitBootstrapKeyError::IncompatibleParameters)
        ));
        assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
    }
    let foreign_client = ClientKey::generate(&parameters(DIMENSION + 1, POLY_LENGTH, 4), &mut rng);
    let mut rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(matches!(
        context.generate_circuit_bootstrap_key(
            &foreign_client,
            &circuit_parameters(context.parameters()),
            &mut rng
        ),
        Err(CircuitBootstrapKeyError::ClientKey(_))
    ));
    assert_eq!(rng.random::<u64>(), untouched_rng.random::<u64>());
}
