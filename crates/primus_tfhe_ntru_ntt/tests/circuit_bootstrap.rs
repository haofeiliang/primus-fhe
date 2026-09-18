#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NlevParameters, NtruParameters, NttNgswCiphertext, NttNtruSecretKey, SecretKeyDistr,
};
use primus_ntt::U64NttTable;
use primus_poly::Polynomial;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, CircuitBootstrapParameters,
    DecompositionConfig, TfheContext, TfheEvaluationError, TfheParameters,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const N: usize = 256;
const Q: u64 = 1_125_899_906_826_241;

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(16, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let accumulator = NtruParameters::new(N, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let tfhe = TfheParameters::try_new(
        lwe,
        NlevParameters::with_ntru_params(&accumulator, 10, None),
        NlevParameters::with_ntru_params(&client, 10, None),
    )
    .unwrap();
    let context = TfheContext::<_, U64NttTable>::try_from_parameters(tfhe).unwrap();
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
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
    let (client, server) = context
        .try_generate_keys(Some(cbs_config), &mut rng)
        .unwrap();
    let circuit_key = server.circuit_bootstrap_key().unwrap();
    let parameters = circuit_key.parameters();
    let key = NttNtruSecretKey::try_from_coeff_secret_key(
        client.accumulator_ntru_secret_key(),
        modulus,
        context.table(),
    )
    .unwrap();
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

    let mut accumulator_client = context.accumulator_client(&client).unwrap();
    let choices = [1u64, 3].map(|message| {
        let mut output = accumulator_client.allocate_ciphertext();
        let (_, allocation) = allocations::measure(|| {
            accumulator_client.encrypt_to(&[message; N], &mut output, &mut rng)
        });
        assert_eq!(
            allocation.count, 0,
            "accumulator encryption must reuse its workspace"
        );
        output
    });

    let mut evaluator = context.circuit_bootstrap_evaluator(&server).unwrap();
    let mut control = evaluator.allocate_output();
    let mut selected = accumulator_client.allocate_ciphertext();
    let mut product = accumulator_client.allocate_ciphertext();
    let mut decoded = vec![0; N];
    let mut decoded_product = vec![0; N];
    // Client shape failures precede sampling or writes, even with reused storage.
    selected.as_mut().fill(7);
    let mut rejected_rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            accumulator_client.encrypt_to(&[0; N - 1], &mut selected, &mut rejected_rng);
        }))
        .is_err()
    );
    assert_eq!(rejected_rng.random::<u64>(), untouched_rng.random::<u64>());
    assert!(selected.as_ref().iter().all(|&value| value == 7));
    decoded.fill(7);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            accumulator_client.decrypt_to(&selected, &mut decoded[..N - 1]);
        }))
        .is_err()
    );
    assert!(decoded.iter().all(|&value| value == 7));
    let short_input = primus_ntru::NtruCiphertext::new(&choices[0].as_ref()[..N - 1]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.external_product_to(&control, &short_input, &mut selected);
        }))
        .is_err()
    );
    assert!(selected.as_ref().iter().all(|&value| value == 7));
    // A zero result must overwrite the previous nonzero control.
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
            "CBS must reuse scratch from its first call"
        );
        let mut phase = Polynomial::new(vec![0u64; N]);
        for (scalar, level) in parameters
            .output_basis()
            .scalar_iter()
            .zip(control.iter_ntt_ntru(N))
        {
            key.phase_to(&level, &mut phase, modulus, context.table());
            for (&actual, &f) in phase
                .as_ref()
                .iter()
                .zip(client.accumulator_ntru_secret_key().as_slice())
            {
                let value = (u128::from(scalar) * u128::from(f.unsigned_abs()) * u128::from(bit))
                    % u128::from(Q);
                let expected = if f < 0 {
                    (u128::from(Q) - value) % u128::from(Q)
                } else {
                    value
                };
                let distance = (u128::from(actual) + u128::from(Q) - expected) % u128::from(Q);
                // Functional bound, below even the third-layer gadget step.
                assert!(distance.min(u128::from(Q) - distance) < (1 << 24));
            }
        }
        assert_eq!(decoded, vec![if bit == 0 { 1 } else { 3 }; N]);
        assert_eq!(decoded_product, vec![3 * bit; N]);
    }
    control.as_mut().fill(7);
    let invalid = primus_tfhe::LweCiphertext::zero(15);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || evaluator.circuit_bootstrap_to(&invalid, &mut control)
        ))
        .is_err()
    );
    assert!(control.as_ref().iter().all(|&value| value == 7));
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let short_len = control.as_ref().len() - 1;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evaluator
            .circuit_bootstrap_to(
                &input,
                &mut NttNgswCiphertext::new(&mut control.as_mut()[..short_len])
            )))
        .is_err()
    );
    assert!(control.as_ref().iter().all(|&value| value == 7));
    for role in 0..3 {
        let output_basis = if role == 0 {
            ApproxSignedBasis::new(Some(Q), 9, Some(levels))
        } else {
            parameters.output_basis().clone()
        };
        let mut parts = [
            parameters.trace().clone(),
            parameters.scheme_switch().clone(),
        ];
        if role > 0 {
            parts[role - 1] = NlevParameters::with_ntru_params(
                &accumulator,
                9,
                Some(parts[role - 1].decompose_length()),
            );
        }
        let [trace, scheme_switch] = parts;
        let foreign = CircuitBootstrapParameters::try_new(
            context.parameters(),
            output_basis,
            trace,
            scheme_switch,
        )
        .unwrap();
        assert!(matches!(
            CircuitBootstrapEvaluator::try_from_parts(&context, &server, &foreign, circuit_key),
            Err(TfheEvaluationError::IncompatibleCircuitBootstrapKey)
        ));
    }
}

#[test]
fn circuit_parameters_check_capacity_ring_and_basis_domain() {
    use primus_tfhe_ntru_ntt::CircuitBootstrapParameterError as Error;
    let modulus = BarrettModulus::new(Q);
    let make = |plain| {
        let acc = NtruParameters::new(N, plain, modulus, SecretKeyDistr::SparseTernary, 0.7);
        let client = NtruParameters::new(N, plain, modulus, SecretKeyDistr::UniformBinary, 0.7);
        TfheParameters::try_new(
            LweParameters::new(16, plain, modulus, SecretKeyDistr::UniformBinary, 0.7),
            NlevParameters::with_ntru_params(&acc, 10, None),
            NlevParameters::with_ntru_params(&client, 10, None),
        )
        .unwrap()
    };
    let tfhe = make(N as u64); // Only two interleaved outputs fit this domain.
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
    assert_eq!(configured.poly_length(), tfhe.poly_length());
    assert_eq!(configured.trace().basis().log_basis(), 9);
    assert_eq!(configured.trace().basis().decompose_length(), 3);
    assert_eq!(
        configured
            .trace()
            .ntru()
            .noise_distribution()
            .standard_deviation(),
        1.25
    );
    assert_eq!(configured.scheme_switch().basis().log_basis(), 10);
    assert_eq!(configured.scheme_switch().basis().decompose_length(), 4);
    assert_eq!(
        configured
            .scheme_switch()
            .ntru()
            .noise_distribution()
            .standard_deviation(),
        2.5
    );
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
    let trace = tfhe.blind_rotation().clone();
    let output = |levels| ApproxSignedBasis::new(Some(Q), 8, Some(levels));
    assert!(
        CircuitBootstrapParameters::try_new(&tfhe, output(2), trace.clone(), trace.clone()).is_ok()
    );
    assert!(matches!(
        CircuitBootstrapParameters::try_new(&tfhe, output(3), trace.clone(), trace.clone()),
        Err(Error::OutputDecompositionTooLarge)
    ));
    let foreign_ring = NtruParameters::new(N * 2, 4, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let foreign_modulus = NtruParameters::new(
        N,
        4,
        BarrettModulus::new(132_120_577u64),
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    for foreign in [&foreign_ring, &foreign_modulus] {
        assert!(matches!(
            CircuitBootstrapParameters::try_new(
                &tfhe,
                output(2),
                NlevParameters::with_ntru_params(foreign, 8, Some(2)),
                trace.clone()
            ),
            Err(Error::PolynomialLengthMismatch { role: "trace" }
                | Error::CipherModulusMismatch { role: "trace" })
        ));
    }
    assert!(matches!(
        CircuitBootstrapParameters::try_new(
            &tfhe,
            ApproxSignedBasis::new(None, 8, Some(2)),
            trace.clone(),
            trace,
        ),
        Err(Error::OutputBasisModulusMismatch)
    ));
}
