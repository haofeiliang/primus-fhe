use primus_decompose::DecompositionBaseLog;
use primus_encoding::RoundedCodec;
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweCiphertext;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_poly::PolyLength;
use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, Lwe, PbsMessageConfig,
    ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_glwe_fourier::{GadgetEncryptionConfig, PbsOrder, PbsParameters, TfheContext};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

// Quantizing to multiples of 4 accumulates one rounding term per nonzero mask.
// N=256 keeps the ManyLUT half-plateau wider than that error budget.
const N: usize = 256;

fn parameters<T: TorusFftValue>(order: PbsOrder) -> PbsParameters<T> {
    let modulus = NativeModulus::new();
    PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(8),
            cipher_modulus: modulus.into(),
            secret_key_distr: SecretKeyDistr::fixed_composition_ternary(8, 2, 2),
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        messages: PbsMessageConfig::new(T::as_from(15u32)).with_output_modulus(T::as_from(8u32)),
        order,
    })
    .unwrap()
}

fn value<T: TorusFftValue>(input: usize, output: usize) -> T {
    match output {
        0 => T::as_from(input % 4),
        1 => T::as_from(input / 4),
        2 => T::as_from(input),
        _ => T::as_from(7 - input),
    }
}

fn check_context<T: TorusFftValue, TABLE>(context_parameters: PbsParameters<T>, table: TABLE)
where
    TABLE: FftTable,
{
    let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4d41_4e59_5042_5301);
    let input_codec = primus_encoding::RoundedCodec::new(
        T::as_from(15u32),
        context.parameters().cipher_modulus(),
    );
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    let encryptor = context
        .encryptor(client_key.external_lwe_secret_key())
        .unwrap();
    let decryptor = context
        .pbs_decryptor(client_key.external_lwe_secret_key())
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    // Input centers use t_in=15; output values use the independent t_out=8 scale.
    let output_codec = RoundedCodec::new(
        T::as_from(8u32),
        context.parameters().small_lwe().cipher_modulus(),
    );
    let compiler = context.pbs_lookup_table_compiler().unwrap();
    // Shared tests cover geometry; keep output counts 1, 3 (padded to 4), and 4 here.
    for output_count in [1, 3, 4] {
        let flat: Vec<_> = (0..8)
            .flat_map(|input| (0..output_count).map(move |output| value(input, output)))
            .collect();
        let lut = compiler
            .compile_interleaved_slice(output_count, &flat)
            .unwrap();
        let mut outputs =
            vec![
                LweCiphertext::zero(context.parameters().external_lwe_dimension().get());
                output_count
            ];
        for message in [0, 3, 4, 7] {
            let input = encryptor
                .encrypt_padded(T::as_from(message), &mut rng)
                .unwrap();
            ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to(
                &mut evaluator,
                input.as_view(),
                &lut,
                &mut outputs,
            );
            if output_count == 3 && message == 3 {
                assert_eq!(
                    outputs,
                    evaluator.apply_interleaved_lookup_table(input.as_view(), &lut)
                );
            }
            for (index, output) in outputs.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt(output.as_view()).unwrap(),
                    value(message, index)
                );
            }
            if output_count == 1 && message == 3 {
                let single = compiler.compile_fn(|input| value(input, 0)).unwrap();
                // Borrow boxed input and a dirty stack sub-slice. The same
                // PBS must overwrite every coefficient in the reused output.
                let input = Lwe::new(input.0.into_boxed_slice());
                let lwe_len = input.lwe_len();
                let mut storage = [T::ONE; N + 3];
                ProgrammableBootstrap::apply_lookup_table_to(
                    &mut evaluator,
                    input.as_view(),
                    &single,
                    Lwe::new(&mut storage[1..1 + lwe_len]),
                );
                assert_eq!(outputs[0].as_ref(), &storage[1..1 + lwe_len]);
                assert_eq!(storage[0], T::ONE);
                assert_eq!(storage[1 + lwe_len], T::ONE);
                assert_eq!(
                    outputs[0],
                    evaluator.apply_lookup_table(input.as_view(), &single)
                );
            }
        }
    }

    // A program chooses its own message scale. Reuse the same client/server
    // keys and evaluator with a different t; ciphertexts carry no codec metadata.
    let other_modulus = T::as_from(4u32);
    let other_codecs = context
        .parameters()
        .pbs_codecs(PbsMessageConfig::new(other_modulus))
        .unwrap();
    let other_input = context
        .parameters()
        .encryptor_with_codec(
            client_key.external_lwe_secret_key(),
            other_codecs.input_codec(),
        )
        .unwrap()
        .encrypt_padded(T::ONE, &mut rng)
        .unwrap();
    let other_lut = context
        .parameters()
        .lookup_table_compiler(&other_codecs)
        .unwrap()
        .compile_fn(|message| T::as_from(1 - message))
        .unwrap();
    let other_output = evaluator.apply_lookup_table(other_input.as_view(), &other_lut);
    assert_eq!(
        context
            .parameters()
            .decryptor_with_codec(
                client_key.external_lwe_secret_key(),
                other_codecs.output_codec()
            )
            .unwrap()
            .decrypt(other_output.as_view())
            .unwrap(),
        T::ZERO
    );

    let input = encryptor
        .encrypt_padded(T::as_from(3u32), &mut rng)
        .unwrap();
    let good = compiler.compile_interleaved_fn(3, value).unwrap();
    let mut outputs = vec![input.clone(); 3];
    // Isolate each piece of LUT metadata, including equal-length wrong-domain tables.
    let mismatched_tables = [
        (
            LookupTable::try_new(
                2,
                PolyLength::new(N / 2),
                T::as_from(15u32),
                NativeModulus::new(),
                NativeModulus::new(),
                |_| Ok(T::ZERO),
            )
            .unwrap(),
            InterleavedLookupTable::try_new(
                2,
                PolyLength::new(N / 2),
                3,
                T::as_from(15u32),
                NativeModulus::new(),
                NativeModulus::new(),
                |_, _| Ok(T::ZERO),
            )
            .unwrap(),
        ),
        (
            LookupTable::try_new(
                2,
                PolyLength::new(N),
                T::as_from(15u32),
                BarrettModulus::new(T::as_from(132_120_577u32)),
                NativeModulus::new(),
                |_| Ok(T::ZERO),
            )
            .unwrap(),
            InterleavedLookupTable::try_new(
                2,
                PolyLength::new(N),
                3,
                T::as_from(15u32),
                BarrettModulus::new(T::as_from(132_120_577u32)),
                NativeModulus::new(),
                |_, _| Ok(T::ZERO),
            )
            .unwrap(),
        ),
        (
            LookupTable::try_new(
                2,
                PolyLength::new(N),
                T::as_from(15u32),
                NativeModulus::new(),
                BarrettModulus::new(T::as_from(132_120_577u32)),
                |_| Ok(T::ZERO),
            )
            .unwrap(),
            InterleavedLookupTable::try_new(
                2,
                PolyLength::new(N),
                3,
                T::as_from(15u32),
                NativeModulus::new(),
                BarrettModulus::new(T::as_from(132_120_577u32)),
                |_, _| Ok(T::ZERO),
            )
            .unwrap(),
        ),
    ];
    for (single, many) in mismatched_tables {
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_lookup_table_to(input.as_view(), &single, outputs[0].as_mut_view());
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut outputs);
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    let single = compiler.compile_fn(|x| T::as_from(x)).unwrap();
    let wrong = LweCiphertext::zero(input.dimension() - 1);
    for bad_input in [false, true] {
        let mut output = if bad_input {
            input.clone()
        } else {
            wrong.clone()
        };
        let before = output.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_lookup_table_to(
                    if bad_input {
                        wrong.as_view()
                    } else {
                        input.as_view()
                    },
                    &single,
                    output.as_mut_view(),
                );
            }))
            .is_err()
        );
        assert_eq!(output, before);
    }
    // Four physical slots still require exactly three output ciphertexts.
    for case in 0..3 {
        let mut outputs = vec![input.clone(); if case == 0 { 4 } else { 3 }];
        if case == 1 {
            outputs[1] = wrong.clone();
        }
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_interleaved_lookup_table_to(
                    if case == 2 {
                        wrong.as_view()
                    } else {
                        input.as_view()
                    },
                    &good,
                    &mut outputs,
                );
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    // Rejected calls and message overrides leave the evaluator and original decoder usable.
    evaluator.apply_interleaved_lookup_table_to(input.as_view(), &good, &mut outputs);
    assert_eq!(
        decryptor.decrypt(outputs[0].as_view()).unwrap(),
        T::as_from(3u32)
    );
    assert_eq!(
        decryptor.decrypt(outputs[1].as_view()).unwrap(),
        T::as_from(0u32)
    );
    assert_eq!(
        decryptor.decrypt(outputs[2].as_view()).unwrap(),
        T::as_from(3u32)
    );

    // A non-power-of-two base and short domain share the same keys and PBS scratch.
    let bivariate = BivariateLookupTable::try_new(
        3,
        2,
        PolyLength::new(N),
        &input_codec,
        &output_codec,
        |x, y| T::as_from(x * x + y),
    )
    .unwrap();
    let mut packed = input.clone();
    let mut result = input;
    for (x, y) in [(T::as_from(2u32), T::ONE), (T::ONE, T::ZERO)] {
        let lhs = encryptor.encrypt_padded(x, &mut rng).unwrap();
        let rhs = encryptor.encrypt_padded(y, &mut rng).unwrap();
        bivariate.pack_to(lhs.as_view(), rhs.as_view(), packed.as_mut_view());
        evaluator.apply_lookup_table_to(
            packed.as_view(),
            bivariate.lookup_table(),
            result.as_mut_view(),
        );
        assert_eq!(decryptor.decrypt(result.as_view()).unwrap(), x * x + y);
    }

    // Reuse this odd-modulus fixture for the full domain, including the upper
    // half. Keep a distinct output scale and a function with f(0) != 0.
    let values: Vec<_> = (0..15).map(|m| T::as_from((m * m + 3) % 8)).collect();
    let full = compiler.compile_odd_full_domain_slice(&values).unwrap();
    // The shared LUT oracle covers all rotations. Encrypted evaluations keep
    // both sides of the fold, the final message and zero after dirty reuse.
    for message in [0, 1, 7, 8, 14, 0] {
        let expected = values[message];
        let input = encryptor.encrypt(T::as_from(message), &mut rng).unwrap();
        evaluator.apply_lookup_table_to(input.as_view(), &full, result.as_mut_view());
        assert_eq!(decryptor.decrypt(result.as_view()).unwrap(), expected);
    }
}

#[test]
fn pbs_u32_preserves_outputs_and_validates_domains() {
    for case in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        check_context(
            parameters::<u32>(case),
            RustFftTable::new(PolyLength::new(N)),
        );
        check_context(
            parameters::<u32>(case),
            TfheFftTable::new(PolyLength::new(N)),
        );
    }
}

#[test]
fn pbs_u64_preserves_outputs_and_validates_domains() {
    for case in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        check_context(
            parameters::<u64>(case),
            RustFftTable::new(PolyLength::new(N)),
        );
        check_context(
            parameters::<u64>(case),
            TfheFftTable::new(PolyLength::new(N)),
        );
    }
}
