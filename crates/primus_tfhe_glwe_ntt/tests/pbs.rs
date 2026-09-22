use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_integer::FheUint;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable, U64NttTable};
use primus_test_allocations as allocations;
use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_glwe_ntt::{PbsOrder, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 256;

fn parameters<T: FheUint>(q: T, order: PbsOrder) -> TfheParameters<T> {
    let modulus = BarrettModulus::new(q);
    let lwe = LweParameters::new(
        8,
        T::as_from(15u32),
        modulus,
        SecretKeyDistr::fixed_composition_ternary(8, 2, 2),
        0.7,
    );
    let glwe = GlweParameters::new(
        1,
        N,
        T::as_from(15u32),
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bsk = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 8, None);
    TfheParameters::try_new(
        lwe,
        glwe,
        bsk,
        ApproxSignedBasis::new(Some(q), 8, None),
        order,
    )
    .unwrap()
}

fn value<T: FheUint>(input: usize, output: usize) -> T {
    match output {
        0 => T::as_from(input % 4),
        1 => T::as_from(input / 4),
        2 => T::as_from(input),
        _ => T::as_from(7 - input),
    }
}

fn check_context<T: FheUint, TABLE>(context: TfheContext<T, TABLE>)
where
    TABLE: primus_ntt::MonomialNttTable<ValueT = T>,
{
    let q = context
        .parameters()
        .small_lwe()
        .cipher_modulus_value()
        .unwrap();
    let mut rng = StdRng::seed_from_u64(0x4d41_4e59_5042_5301);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    // Input centers use t_in=15; output values use the independent t_out=8 scale.
    let output_codec = RoundedCodec::new(
        T::as_from(8u32),
        context.parameters().small_lwe().cipher_modulus(),
    );
    // Shared tests cover geometry; keep output counts 1, 3 (padded to 4), and 4 here.
    for output_count in [1, 3, 4] {
        let flat: Vec<_> = (0..8)
            .flat_map(|input| (0..output_count).map(move |output| value(input, output)))
            .collect();
        let lut = context
            .parameters()
            .compile_interleaved_lookup_table_with_codec_slice(&output_codec, output_count, &flat)
            .unwrap();
        let mut outputs =
            vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); output_count];
        for message in [0, 3, 4, 7] {
            let input = encryptor
                .encrypt_padded(T::as_from(message), &mut rng)
                .unwrap();
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
                let single = context
                    .parameters()
                    .compile_lookup_table_with_codec_fn(&output_codec, |input| value(input, 0))
                    .unwrap();
                let mut output = outputs[0].clone();
                let (_, allocation) = allocations::measure(|| {
                    evaluator.apply_lookup_table_to(&input, &single, &mut output);
                });
                assert_eq!(allocation.count, 0, "PBS must reuse its workspace");
                assert_eq!(outputs[0], output);
                assert_eq!(outputs[0], evaluator.apply_lookup_table(&input, &single));
            }
        }
    }

    let input = encryptor
        .encrypt_padded(T::as_from(3u32), &mut rng)
        .unwrap();
    let good = context
        .parameters()
        .compile_interleaved_lookup_table_with_codec_fn(&output_codec, 3, value)
        .unwrap();
    let mut outputs = vec![input.clone(); 3];
    // Isolate each piece of LUT metadata, including equal-length wrong-domain tables.
    let mut mismatched_tables = Vec::new();
    for (n, t) in [(N / 2, 15), (N, 8)] {
        mismatched_tables.push((
            LookupTable::try_new(
                2,
                n,
                T::as_from(t),
                BarrettModulus::new(q),
                BarrettModulus::new(q),
                |_| Ok(T::ZERO),
            )
            .unwrap(),
            InterleavedLookupTable::try_new(
                2,
                n,
                3,
                T::as_from(t),
                BarrettModulus::new(q),
                BarrettModulus::new(q),
                |_, _| Ok(T::ZERO),
            )
            .unwrap(),
        ));
    }
    mismatched_tables.push((
        LookupTable::try_new(
            2,
            N,
            T::as_from(15u32),
            primus_modulus::NativeModulus::new(),
            BarrettModulus::new(q),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            N,
            3,
            T::as_from(15u32),
            primus_modulus::NativeModulus::new(),
            BarrettModulus::new(q),
            |_, _| Ok(T::ZERO),
        )
        .unwrap(),
    ));
    mismatched_tables.push((
        LookupTable::try_new(
            2,
            N,
            T::as_from(15u32),
            BarrettModulus::new(q),
            BarrettModulus::new(T::as_from(104_857_601u32)),
            |_| Ok(T::ZERO),
        )
        .unwrap(),
        InterleavedLookupTable::try_new(
            2,
            N,
            3,
            T::as_from(15u32),
            BarrettModulus::new(q),
            BarrettModulus::new(T::as_from(104_857_601u32)),
            |_, _| Ok(T::ZERO),
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
    let single = context
        .parameters()
        .compile_lookup_table_with_codec_fn(&output_codec, |x| T::as_from(x))
        .unwrap();
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
        T::as_from(3u32)
    );
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(&outputs[1]).unwrap()),
        T::as_from(0u32)
    );
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(&outputs[2]).unwrap()),
        T::as_from(3u32)
    );

    // A non-power-of-two base and short domain share the same keys and PBS scratch.
    let bivariate = BivariateLookupTable::try_new(
        3,
        2,
        N,
        context.parameters().input_plaintext_codec(),
        &output_codec,
        |x, y| T::as_from(x * x + y),
    )
    .unwrap();
    let mut packed = input.clone();
    let mut result = input;
    for (x, y) in [(T::as_from(2u32), T::ONE), (T::ONE, T::ZERO)] {
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
    let values: Vec<_> = (0..15).map(|m| T::as_from((m * m + 3) % 8)).collect();
    let full = context
        .parameters()
        .compile_odd_full_domain_lookup_table_with_codec_slice(&output_codec, &values)
        .unwrap();
    for (message, &expected) in values.iter().enumerate() {
        let input = encryptor.encrypt(T::as_from(message), &mut rng).unwrap();
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
fn pbs_u32_preserves_outputs_and_validates_domains() {
    let q = 132_120_577u32;
    for case in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = U32NttTable::new(N.trailing_zeros(), BarrettModulus::new(q)).unwrap();
        check_context(TfheContext::try_new(parameters(q, case), table).unwrap());
    }
}

#[test]
fn pbs_u64_preserves_outputs_and_validates_domains() {
    let q = 1_125_899_906_826_241u64;
    for case in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = U64NttTable::new(N.trailing_zeros(), BarrettModulus::new(q)).unwrap();
        check_context(TfheContext::try_new(parameters(q, case), table).unwrap());
    }
}
