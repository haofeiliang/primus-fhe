use primus_lwe::{LweCiphertext, LweParameters};
use primus_tfhe::{
    ProgrammableBootstrapMany, compile_encoded_lookup_table, compile_encoded_many_lookup_table,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};
const N: usize = 256;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_glwe::{GgswParameters, GlweParameters, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_tfhe_glwe_fourier::{PbsOrder, TfheContext, TfheParameters};
fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    let modulus = NativeModulus::new();
    let lwe = LweParameters::new(8, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let glwe = GlweParameters::new(1, N, 16, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let bsk = GgswParameters::with_glwe_params(&glwe, 8, None);
    TfheParameters::try_new(lwe, glwe, bsk, ApproxSignedBasis::new(None, 8, None), order).unwrap()
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
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    for output_count in [1, 2, 4] {
        let flat: Vec<_> = (0..8)
            .flat_map(|input| (0..output_count).map(move |output| value(input, output)))
            .collect();
        let lut = context
            .compile_many_lookup_table_slice(output_count, &flat)
            .unwrap();
        let mut outputs = vec![
            LweCiphertext::zero(context.parameters().ciphertext_lwe_dimension());
            output_count
        ];
        for message in 0..8 {
            let input = encryptor.encrypt_padded(message as u32, &mut rng).unwrap();
            if message == 0 {
                outputs = evaluator.apply_many_lookup_table(&input, &lut);
            } else {
                // Exercise the representation-independent consumption boundary too.
                ProgrammableBootstrapMany::apply_many_lookup_table_to(
                    &mut evaluator,
                    &input,
                    &lut,
                    &mut outputs,
                );
            }
            for (index, output) in outputs.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt::<u32>(output).unwrap(),
                    value(message, index)
                );
            }
            if output_count == 1 {
                let single = context
                    .compile_lookup_table_fn(|input| value(input, 0))
                    .unwrap();
                assert_eq!(outputs[0], evaluator.apply_lookup_table(&input, &single));
            }
        }
    }

    let input = encryptor.encrypt_padded(3u32, &mut rng).unwrap();
    let good = context.compile_many_lookup_table_fn(2, value).unwrap();
    let mut outputs = vec![input.clone(); 2];
    // Isolate each piece of LUT metadata, including equal-length wrong-domain tables.
    let mut mismatched_tables = Vec::new();
    for (n, t, input_q) in [(N / 2, 16, None), (N, 8, None), (N, 16, Some(132_120_577))] {
        mismatched_tables.push((
            compile_encoded_lookup_table(2, n, t, input_q, NativeModulus::new(), |_| Ok(0))
                .unwrap(),
            compile_encoded_many_lookup_table(2, n, 2, t, input_q, NativeModulus::new(), |_, _| {
                Ok(0)
            })
            .unwrap(),
        ));
    }
    mismatched_tables.push((
        compile_encoded_lookup_table(2, N, 16, None, BarrettModulus::new(132_120_577), |_| Ok(0))
            .unwrap(),
        compile_encoded_many_lookup_table(
            2,
            N,
            2,
            16,
            None,
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
                evaluator.apply_many_lookup_table_to(&input, &many, &mut outputs);
            }))
            .is_err()
        );
        assert_eq!(outputs, before);
    }
    let single = context.compile_lookup_table_fn(|x| x as u32).unwrap();
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
    for case in 0..3 {
        let mut outputs = vec![input.clone(); if case == 0 { 1 } else { 2 }];
        if case == 1 {
            outputs[1] = wrong.clone();
        }
        let before = outputs.clone();
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.apply_many_lookup_table_to(
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
    evaluator.apply_many_lookup_table_to(&input, &good, &mut outputs);
    assert_eq!(decryptor.decrypt::<u32>(&outputs[0]).unwrap(), 3);
    assert_eq!(decryptor.decrypt::<u32>(&outputs[1]).unwrap(), 0);
}
#[test]
fn many_pbs_preserves_outputs_and_validates_domains() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        check_context(
            TfheContext::try_new(
                parameters(order),
                RustFftTable::new(N.trailing_zeros()).unwrap(),
            )
            .unwrap(),
        );
        check_context(
            TfheContext::try_new(
                parameters(order),
                TfheFftTable::new(N.trailing_zeros()).unwrap(),
            )
            .unwrap(),
        );
    }
}
