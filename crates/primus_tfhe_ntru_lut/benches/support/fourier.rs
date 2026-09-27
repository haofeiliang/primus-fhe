include!("../../src/fourier.rs");

mod measurements {
    use super::*;
    use crate::support::*;
    use criterion::{BatchSize, Criterion};
    use primus_encoding::{PlaintextEmbedding, RoundedCodec};
    use primus_ntru::{
        FourierNlevCiphertext, FourierNtruCmuxContext, FourierNtruGadgetEncryptContext,
        FourierNtruSecretKey, FourierNtruTraceContext,
    };
    use primus_test_allocations::measure;
    use primus_tfhe_ntru_fourier::{CircuitBootstrapEvaluator, KeyGenerator};
    use rand::{SeedableRng, rngs::StdRng};
    use std::hint::black_box;
    pub(crate) fn benchmark<Table: FftTable>(c: &mut Criterion, backend: &str) {
        let modulus = NativeModulus::<u64>::new();
        let context = TfheContext::<_, Table, _>::try_from_parameters(parameters(modulus)).unwrap();
        let name = format!("ntru_lookup/{backend}/N{N}/n{DIMENSION}/M4/c7/d5/o3");
        let mut rng = StdRng::seed_from_u64(0x0053_5445_5039);
        let mut generator = KeyGenerator::new(&context);
        let client = generator.try_generate_client_key(&mut rng).unwrap();
        let (server, memory) = measure(|| {
            generator
                .try_generate_server_key(&client, Some(cbs()), &mut rng)
                .unwrap()
        });
        heap(&format!("{name}/server_key"), memory);
        eprintln!(
            "memory,{name}/return_key_coefficients,{}",
            size_of_val(server.key_switching_key().as_slice())
        );
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let (table, memory) = measure(|| {
            HighPrecisionLookupTable::try_new(context.parameters(), CONFIG, digit).unwrap()
        });
        heap(&format!("{name}/compiled_table"), memory);
        let (mut evaluator, memory) =
            measure(|| FourierLookupTableEvaluator::try_new(&context, &server, &table).unwrap());
        heap(&format!("{name}/lookup_workspace"), memory);
        let (mut output, memory) = measure(|| evaluator.allocate_output());
        heap(&format!("{name}/lookup_outputs"), memory);
        let cases = [0usize, 0x1234, (1 << 14) - 1];
        let inputs: Vec<Vec<_>> = cases
            .iter()
            .map(|&x| {
                (0..CONFIG.input_chunk_count)
                    .map(|i| {
                        encryptor
                            .encrypt_padded(((x >> (2 * i)) & 3) as u64, &mut rng)
                            .unwrap()
                    })
                    .collect()
            })
            .collect();
        // Check complete semantics on zero, mixed digits and the domain endpoint.
        // Noise is measured against the known result, separately from decoding.
        let q = 1u64 << 24;
        let mut max_error = 0;
        for (&x, input) in cases.iter().zip(&inputs) {
            let (_, memory) = measure(|| evaluator.evaluate_to(input, &mut output));
            assert_eq!(memory.count, 0);
            for (j, value) in output.iter().enumerate() {
                let expected = digit(x, j);
                assert_eq!(
                    decryptor.decrypt(value).unwrap(),
                    expected,
                    "{name}: x={x}, output={j}"
                );
                let phase = client
                    .external_lwe_secret_key()
                    .as_view()
                    .decrypt_phase(value, context.parameters().external_lwe().cipher_modulus());
                let distance = (phase + q - expected * (q / 8)) % q;
                max_error = max_error.max(distance.min(q - distance));
            }
        }
        eprintln!(
            "phase_error,{name}/complete,max_abs_q_units={max_error},samples={}",
            cases.len() * CONFIG.output_chunk_count
        );
        let input = &inputs[1];
        bench(c, &format!("{name}/complete"), || {
            evaluator.evaluate_to(black_box(input), black_box(&mut output));
            black_box(&output);
        });
        // prepare_selectors runs only once before these two stage measurements.
        evaluator.prepare_selectors(input);
        bench(
            c,
            &format!("{name}/table_selection/prepared_selectors"),
            || {
                evaluator.select_table(black_box(0));
                black_box(evaluator.current.as_ref());
            },
        );
        let selected = evaluator.current.clone();
        let (_, memory) = measure(|| evaluator.rotate_selected_table());
        assert_eq!(memory.count, 0);
        eprintln!(
            "online_allocations,{name}/rotation_selection/prepared_controls,{}",
            memory.count
        );
        let rotated = evaluator.current.clone();
        // Restore a fresh copy outside each timed batch. Feeding a previous rotation's
        // result back would change both the plaintext and accumulated noise per sample.
        c.bench_function(
            &format!("{name}/rotation_selection/prepared_controls"),
            |b| {
                b.iter_batched_ref(
                    || selected.clone(),
                    |state| {
                        core::mem::swap(&mut evaluator.current, state);
                        evaluator.rotate_selected_table();
                        core::mem::swap(&mut evaluator.current, state);
                        black_box(state.as_ref());
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        bench(c, &format!("{name}/return_Q_to_q_then_KS"), || {
            server.key_switching_key().key_switch_to(
                black_box(&rotated),
                &mut output[0],
                context.parameters().external_lwe().cipher_modulus(),
                &mut evaluator.return_context,
            );
            black_box(output[0].as_ref());
        });
        assert_eq!(decryptor.decrypt(&output[0]).unwrap(), digit(cases[1], 0));

        let (mut one_hot, memory) =
            measure(|| OneHotCircuitBootstrapEvaluator::try_new(&context, &server).unwrap());
        heap(&format!("{name}/one_hot_workspace"), memory);
        let mut full = one_hot.allocate_ngsw_output();
        let mut nonzero = one_hot.allocate_nonzero_ngsw_output();
        eprintln!(
            "memory,{name}/one_hot_full_output,{}",
            size_of_val(full.as_slice())
        );
        eprintln!(
            "memory,{name}/one_hot_nonzero_output,{}",
            size_of_val(nonzero.as_slice())
        );
        bench(c, &format!("{name}/one_hot/full_ngsw"), || {
            one_hot.one_hot_ngsw_to(black_box(&input[0]), &mut full);
            black_box(&full);
        });
        bench(c, &format!("{name}/one_hot/nonzero_ngsw"), || {
            one_hot.one_hot_nonzero_ngsw_to(black_box(&input[0]), &mut nonzero);
            black_box(&nonzero);
        });
        assert_eq!(nonzero, full[full.len() / 4..]);

        let bit = encryptor.encrypt_padded(1, &mut rng).unwrap();
        let (mut cbs, memory) =
            measure(|| CircuitBootstrapEvaluator::try_new(&context, &server).unwrap());
        heap(&format!("{name}/cbs_workspace"), memory);
        let mut control = cbs.allocate_output();
        let mut ring_client = context.accumulator_client(&client).unwrap();
        let choices = [0, 3].map(|m| ring_client.encrypt(&vec![m; N], &mut rng));
        let mut ring_output = context.allocate_accumulator_ciphertext();
        let mut decoded = vec![0u64; N];
        cbs.circuit_bootstrap_to(&bit, &mut control);
        cbs.cmux_to(&control, &choices[0], &choices[1], &mut ring_output);
        ring_client.decrypt_to(&ring_output, &mut decoded);
        assert_eq!(decoded, vec![3; N]);
        bench(c, &format!("{name}/ordinary_cbs"), || {
            cbs.circuit_bootstrap_to(black_box(&bit), &mut control);
            black_box(control.as_ref());
        });

        // Independent encryption of the first-coordinate selector; use the same BR
        // basis and f as the initializer. This measures binary fused lifting alone.
        let mut fft = context.new_fft_engine();
        let secret = FourierNtruSecretKey::try_from_coeff_secret_key(
            client.accumulator_ntru_secret_key(),
            &mut fft,
        )
        .unwrap();
        let br = context.parameters().blind_rotation();
        let mut positive = FourierNlevCiphertext::<Vec<_>>::zero(br.fourier_nlev_len());
        secret.encrypt_nlev_constant_to(
            1u64,
            &mut positive,
            br,
            &mut fft,
            &mut rng,
            &mut FourierNtruGadgetEncryptContext::new(N),
        );
        let (mut lift, memory) =
            measure(|| FourierNtruCmuxContext::<u64>::new(N, br.decompose_length()));
        heap(&format!("{name}/first_lift_workspace"), memory);
        let codec = RoundedCodec::new(8, modulus);
        let messages: Vec<_> = (0..N).map(|i| ((1 + i + i / (N / 4)) % 4) as u64).collect();
        let public = Polynomial::new(
            messages
                .iter()
                .map(|&v| codec.encode_value(v, PlaintextEmbedding::Unsigned))
                .collect::<Vec<_>>(),
        );
        let exponent = N / 3;
        server.initializer().lift_monomial_to(
            &positive,
            None,
            black_box(&public),
            black_box(exponent),
            &mut ring_output,
            br.basis(),
            &mut fft,
            &mut lift,
        );
        ring_client.decrypt_to(&ring_output, &mut decoded);
        for (i, &m) in messages.iter().enumerate() {
            let expected = if i + exponent < N { m } else { (8 - m) % 8 };
            assert_eq!(decoded[(i + exponent) % N], expected);
        }
        bench(c, &format!("{name}/first_lift/binary"), || {
            server.initializer().lift_monomial_to(
                &positive,
                None,
                black_box(&public),
                black_box(exponent),
                &mut ring_output,
                br.basis(),
                &mut fft,
                &mut lift,
            );
            black_box(ring_output.as_ref());
        });

        let trace = server.circuit_bootstrap_key().unwrap().trace_key();
        let trace_input = ring_client.encrypt(&messages, &mut rng);
        let (mut trace_context, memory) = measure(|| FourierNtruTraceContext::new(N));
        heap(&format!("{name}/trace_workspace"), memory);
        for retained in [1, 4] {
            trace.apply_reverse_partial_to(
                black_box(&trace_input),
                retained,
                &mut ring_output,
                &mut fft,
                &mut trace_context,
            );
            ring_client.decrypt_to(&ring_output, &mut decoded);
            for (i, &v) in decoded.iter().enumerate() {
                assert_eq!(
                    v,
                    if i % (N / retained) == 0 {
                        messages[i]
                    } else {
                        0
                    }
                );
            }
            bench(
                c,
                &format!("{name}/reverse_trace/retained{retained}"),
                || {
                    trace.apply_reverse_partial_to(
                        black_box(&trace_input),
                        retained,
                        &mut ring_output,
                        &mut fft,
                        &mut trace_context,
                    );
                    black_box(ring_output.as_ref());
                },
            );
        }
    }
}

pub(super) use measurements::benchmark;
