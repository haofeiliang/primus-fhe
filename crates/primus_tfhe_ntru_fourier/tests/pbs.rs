#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_ntru::{NlevParameters, NtruParameters, SecretKeyDistr};
use primus_reduce::ReduceAdd;
use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_ntru_fourier::{TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const N: usize = 256;

fn parameters() -> TfheParameters<u32> {
    let modulus = NativeModulus::new();
    let lwe = LweParameters::new(3, 15, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let acc = NtruParameters::new(N, 15, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let client = NtruParameters::new(N, 15, modulus, SecretKeyDistr::UniformBinary, 0.7);
    TfheParameters::try_new(
        lwe,
        NlevParameters::with_ntru_params(&acc, 8, None),
        NlevParameters::with_ntru_params(&client, 8, None),
    )
    .unwrap()
}

fn value(input: usize, output: usize) -> u32 {
    match output {
        0 => (input % 4) as u32,
        1 => (input / 4) as u32,
        2 => input as u32,
        _ => (7 - input) as u32,
    }
}

fn check_context<TABLE>(context: TfheContext<u32, TABLE>)
where
    TABLE: FftTable,
{
    let mut rng = StdRng::seed_from_u64(0x4d41_4e59_5042_5301);
    let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
    let public = client_key
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let public_encryptor = context.encryptor(&public).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    // Input centers use t_in=15; output values use the independent t_out=8 scale.
    let output_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());
    let single = context
        .parameters()
        .compile_lookup_table_fn(&output_codec, |input| value(input, 0))
        .unwrap();
    let mut output = LweCiphertext::zero(context.parameters().external_lwe_dimension());
    // Noise-free LWE inputs force zero, odd and even numbers of CMUX steps.
    // Reuse the same evaluator across all paths to check the final buffer role.
    let modulus = context.parameters().external_lwe().cipher_modulus();
    for active_count in [0, 1, 2, 3, 1, 0] {
        let mut input = LweCiphertext::zero(context.parameters().external_lwe_dimension());
        input.a_mut()[..active_count].fill(1u32 << 30);
        let mut body = context
            .parameters()
            .input_plaintext_codec()
            .encode_value(3, PlaintextEmbedding::Unsigned);
        for (&mask, &secret) in input
            .a()
            .iter()
            .zip(client_key.external_lwe_secret_coefficients())
        {
            if secret == 1 {
                body = modulus.reduce_add(body, mask);
            }
        }
        *input.b_mut() = body;
        let (_, allocation) = allocations::measure(|| {
            evaluator.apply_lookup_table_to(&input, &single, &mut output);
        });
        assert_eq!(
            allocation.count, 0,
            "PBS must reuse both accumulator buffers"
        );
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap()),
            3
        );
    }
    // Shared tests cover geometry; keep output counts 1, 3 (padded to 4), and 4 here.
    for output_count in [1, 3, 4] {
        let flat: Vec<_> = (0..8)
            .flat_map(|input| (0..output_count).map(move |output| value(input, output)))
            .collect();
        let lut = context
            .parameters()
            .compile_interleaved_lookup_table_slice(&output_codec, output_count, &flat)
            .unwrap();
        let mut outputs =
            vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); output_count];
        for message in [0, 3, 4, 7] {
            let input = encryptor.encrypt_padded(message as u32, &mut rng).unwrap();
            let (_, allocation) = allocations::measure(|| {
                ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to(
                    &mut evaluator,
                    &input,
                    &lut,
                    &mut outputs,
                );
            });
            assert_eq!(allocation.count, 0, "PBSManyLUT must reuse its workspace");
            if output_count == 3 && message == 3 {
                assert_eq!(
                    outputs,
                    evaluator.apply_interleaved_lookup_table(&input, &lut)
                );
            }
            for (index, output) in outputs.iter().enumerate() {
                assert_eq!(
                    output_codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                    value(message, index)
                );
            }
            if output_count == 1 && message == 3 {
                let (_, allocation) = allocations::measure(|| {
                    evaluator.apply_lookup_table_to(&input, &single, &mut output);
                });
                assert_eq!(allocation.count, 0, "PBS must reuse its workspace");
                assert_eq!(outputs[0], output);
                assert_eq!(outputs[0], evaluator.apply_lookup_table(&input, &single));
                let public_input = public_encryptor
                    .encrypt_padded(message as u32, &mut rng)
                    .unwrap();
                evaluator.apply_lookup_table_to(&public_input, &single, &mut output);
                assert_eq!(
                    output_codec.decode_value(decryptor.decrypt_phase(&output).unwrap()),
                    value(message, 0)
                );
            }
        }
    }

    let input = encryptor.encrypt_padded(3u32, &mut rng).unwrap();
    let good = context
        .parameters()
        .compile_interleaved_lookup_table_fn(&output_codec, 3, value)
        .unwrap();
    let mut outputs = vec![input.clone(); 3];
    // Isolate each piece of LUT metadata, including equal-length wrong-domain tables.
    let mut mismatched_tables = Vec::new();
    for (n, t) in [(N / 2, 15), (N, 8)] {
        mismatched_tables.push((
            LookupTable::try_new(2, n, t, NativeModulus::new(), NativeModulus::new(), |_| {
                Ok(0)
            })
            .unwrap(),
            InterleavedLookupTable::try_new(
                2,
                n,
                3,
                t,
                NativeModulus::new(),
                NativeModulus::new(),
                |_, _| Ok(0),
            )
            .unwrap(),
        ));
    }
    mismatched_tables.push((
        LookupTable::try_new(
            2,
            N,
            15,
            BarrettModulus::new(132_120_577),
            NativeModulus::new(),
            |_| Ok(0),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            N,
            3,
            15,
            BarrettModulus::new(132_120_577),
            NativeModulus::new(),
            |_, _| Ok(0),
        )
        .unwrap(),
    ));
    mismatched_tables.push((
        LookupTable::try_new(
            2,
            N,
            15,
            NativeModulus::new(),
            BarrettModulus::new(132_120_577),
            |_| Ok(0),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            N,
            3,
            15,
            NativeModulus::new(),
            BarrettModulus::new(132_120_577),
            |_, _| Ok(0),
        )
        .unwrap(),
    ));
    for (single, many) in mismatched_tables {
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_lookup_table_to(&input, &single, &mut outputs[0]);
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_interleaved_lookup_table_to(&input, &many, &mut outputs);
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
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
                    if bad_input { &wrong } else { &input },
                    &single,
                    &mut output,
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
                    if case == 2 { &wrong } else { &input },
                    &good,
                    &mut outputs,
                );
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    // Rejected calls leave the reusable evaluator usable.
    evaluator.apply_interleaved_lookup_table_to(&input, &good, &mut outputs);
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(&outputs[0]).unwrap()),
        3
    );
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(&outputs[1]).unwrap()),
        0
    );
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(&outputs[2]).unwrap()),
        3
    );

    // A non-power-of-two base and short domain share the same keys and PBS scratch.
    let bivariate = BivariateLookupTable::try_new(
        3,
        2,
        N,
        context.parameters().input_plaintext_codec(),
        &output_codec,
        |x, y| (x * x + y) as u32,
    )
    .unwrap();
    let mut packed = input.clone();
    let mut result = input;
    for (x, y) in [(2u32, 1u32), (1, 0)] {
        let lhs = encryptor.encrypt_padded(x, &mut rng).unwrap();
        let rhs = encryptor.encrypt_padded(y, &mut rng).unwrap();
        let (_, allocation) = allocations::measure(|| {
            bivariate.pack_to(&lhs, &rhs, &mut packed);
            evaluator.apply_lookup_table_to(&packed, bivariate.lookup_table(), &mut result);
        });
        assert_eq!(allocation.count, 0, "packing and PBS must reuse storage");
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&result).unwrap()),
            x * x + y
        );
    }

    // Reuse this odd-modulus fixture for the full domain, including the upper
    // half. Keep a distinct output scale and a function with f(0) != 0.
    let values: Vec<_> = (0..15).map(|m| ((m * m + 3) % 8) as u32).collect();
    let full = context
        .parameters()
        .compile_odd_full_domain_lookup_table_slice(&output_codec, &values)
        .unwrap();
    for (message, &expected) in values.iter().enumerate() {
        let input = encryptor.encrypt(message as u32, &mut rng).unwrap();
        let (_, allocation) = allocations::measure(|| {
            evaluator.apply_lookup_table_to(&input, &full, &mut result);
        });
        assert_eq!(allocation.count, 0, "full-domain PBS must reuse storage");
        assert_eq!(
            output_codec.decode_value(decryptor.decrypt_phase(&result).unwrap()),
            expected
        );
    }
}
#[test]
fn pbs_preserves_outputs_and_validates_domains() {
    check_context(
        TfheContext::try_new(parameters(), RustFftTable::new(N.trailing_zeros()).unwrap()).unwrap(),
    );
    check_context(
        TfheContext::try_new(parameters(), TfheFftTable::new(N.trailing_zeros()).unwrap()).unwrap(),
    );
}
