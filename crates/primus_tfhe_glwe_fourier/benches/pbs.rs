//! PBS stages and complete evaluations with precomputed keys and reusable scratch.
//! Outputs and scratch are reused; setup is not timed.
//!
//! cargo bench -p primus_tfhe_glwe_fourier --bench pbs

use primus_tfhe_test_support::benchmark::{GLWE_STD_DEV, LWE_STD_DEV, PBS_WORKLOADS, PbsWorkload};
use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_glwe::{FourierGlweKeySwitchingContext, GlweCiphertext, GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BooleanGate, BootstrappingKey, FourierGlweBlindRotationContext, PbsOrder, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

fn parameters<T: TorusFftValue>(order: PbsOrder, workload: PbsWorkload) -> TfheParameters<T> {
    let q = 2.0f64.powi(T::BITS as i32);
    let t = T::as_from(workload.plaintext_modulus);
    let lwe = LweParameters::new(
        workload.lwe_dimension,
        t,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        q * LWE_STD_DEV,
    );
    let glwe = GlweParameters::new(
        1,
        workload.poly_length,
        t,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        (q * GLWE_STD_DEV).max(6.4),
    );
    let (pbs_base, pbs_level, ks_base, ks_level) = if T::BITS == 64 {
        (23, 1, 3, 5)
    } else {
        (8, 3, 2, 13)
    };
    TfheParameters::try_new(
        lwe,
        glwe,
        ApproxSignedBasis::new(None, pbs_base, Some(pbs_level)),
        ApproxSignedBasis::new(None, ks_base, Some(ks_level)),
        order,
    )
    .unwrap()
}

fn order_name(order: PbsOrder) -> &'static str {
    match order {
        PbsOrder::BootstrapKeyswitch => "pbs_ks",
        PbsOrder::KeyswitchBootstrap => "ks_pbs",
    }
}

fn bench_order<T: TorusFftValue, Table: FftTable>(
    c: &mut Criterion,
    order: PbsOrder,
    backend: &str,
    workload: PbsWorkload,
) {
    let poly_length = workload.poly_length;
    let table = Table::new(poly_length.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters::<T>(order, workload), table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let BootstrappingKey::Classic(bootstrapping_key) = server_key.bootstrapping_key() else {
        panic!("classic benchmark requires a classic key");
    };
    let parameters = context.parameters();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input_domain = workload.plaintext_modulus as usize / 2;
    let input = encryptor.encrypt_padded(T::ONE, &mut rng).unwrap();
    let lookup_table = context
        .parameters()
        .compile_lookup_table_fn(|x| T::as_from((x + input_domain - 1) % (input_domain)))
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = input.clone();
    let decryptor = context.decryptor(&client_key).unwrap();
    for message in 0..input_domain {
        let probe = encryptor
            .encrypt_padded(T::as_from(message), &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(&probe, &lookup_table, &mut output);
        assert_eq!(
            decryptor.decrypt(&output).unwrap(),
            T::as_from((message + input_domain - 1) % (input_domain))
        );
    }

    let modulus = parameters.accumulator_glwe().cipher_modulus();
    let mut fft = context.new_fft_engine();
    let mut blind_rotation = FourierGlweBlindRotationContext::new(bootstrapping_key);
    let key_switching_parameters = parameters.glwe_key_switching().output();
    let mut key_switching =
        FourierGlweKeySwitchingContext::new(key_switching_parameters.glwe_size());
    let mut main_glwe: GlweCiphertext<Vec<T>> =
        GlweCiphertext::zero(parameters.accumulator_glwe().glwe_len());
    let mut switched: GlweCiphertext<Vec<T>> =
        GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
    let mut small_lwe: LweCiphertext<T> = LweCiphertext::zero(parameters.small_lwe().dimension());

    match order {
        PbsOrder::BootstrapKeyswitch => bootstrapping_key.fourier_blind_rotate_lookup_table_to(
            &input,
            lookup_table.polynomial(),
            &mut main_glwe,
            &mut fft,
            &mut blind_rotation,
        ),
        PbsOrder::KeyswitchBootstrap => {
            input.inverse_extract_glwe_to(&mut main_glwe, poly_length, modulus)
        }
    }
    server_key.glwe_key_switching_key().key_switch_to(
        &main_glwe,
        &mut switched,
        &mut fft,
        &mut key_switching,
    );
    switched.extract_compact_lwe_to(&mut small_lwe, poly_length, modulus);

    let mut group = c.benchmark_group(format!(
        "glwe_fourier/{backend}/{}/u{}/{}/n{}_N{poly_length}_k1",
        workload.name,
        T::BITS,
        order_name(order),
        parameters.small_lwe().dimension(),
    ));
    group.sample_size(10);

    group.bench_function("glwe_key_switching", |b| {
        b.iter(|| {
            server_key.glwe_key_switching_key().key_switch_to(
                black_box(&main_glwe),
                black_box(&mut switched),
                &mut fft,
                &mut key_switching,
            );
            black_box(&switched);
        });
    });
    group.bench_function("blind_rotation", |b| {
        let blind_rotation_input = match order {
            PbsOrder::BootstrapKeyswitch => &input,
            PbsOrder::KeyswitchBootstrap => &small_lwe,
        };
        b.iter(|| {
            black_box(bootstrapping_key).fourier_blind_rotate_lookup_table_to(
                black_box(blind_rotation_input),
                black_box(lookup_table.polynomial()),
                black_box(&mut main_glwe),
                &mut fft,
                &mut blind_rotation,
            );
            black_box(&main_glwe);
        });
    });
    group.bench_function("complete_pbs_reused_output", |b| {
        b.iter(|| {
            evaluator.apply_lookup_table_to(
                black_box(&input),
                black_box(&lookup_table),
                black_box(&mut output),
            );
            black_box(&output);
        });
    });
    if workload.plaintext_modulus == 4 {
        let boolean_encryptor = context.boolean_encryptor(&client_key).unwrap();
        let boolean_lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
        let boolean_rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
        let mut boolean_output = boolean_lhs.clone();
        let mut boolean_evaluator = context.boolean_evaluator(&server_key).unwrap();
        let boolean_decryptor = context.boolean_decryptor(&client_key).unwrap();
        boolean_evaluator.evaluate_binary_to(
            BooleanGate::And,
            &boolean_lhs,
            &boolean_rhs,
            &mut boolean_output,
        );
        assert!(!boolean_decryptor.decrypt(&boolean_output).unwrap());
        boolean_evaluator.mux_to(
            &boolean_lhs,
            &boolean_lhs,
            &boolean_rhs,
            &mut boolean_output,
        );
        assert!(boolean_decryptor.decrypt(&boolean_output).unwrap());

        // One PBS for a binary gate; two PBS calls for MUX.
        group.bench_function("boolean_and", |b| {
            b.iter(|| {
                boolean_evaluator.evaluate_binary_to(
                    BooleanGate::And,
                    black_box(&boolean_lhs),
                    black_box(&boolean_rhs),
                    black_box(&mut boolean_output),
                );
                black_box(&boolean_output);
            });
        });
        group.bench_function("boolean_mux", |b| {
            b.iter(|| {
                boolean_evaluator.mux_to(
                    black_box(&boolean_lhs),
                    black_box(&boolean_lhs),
                    black_box(&boolean_rhs),
                    black_box(&mut boolean_output),
                );
                black_box(&boolean_output);
            });
        });
    }
    // Four interleaved lanes coarsen modulus switching. The t=32/N=2048
    // reference geometry only budgets for single-output PBS.
    if workload.plaintext_modulus == 4 {
        // Each iteration produces the same 3/4 function outputs. Compare shared
        // BR/KS against separate PBS calls; k=3 also exercises a padded fourth slot.
        // All tables, keys and outputs are reused.
        for count in [3, 4] {
            let value = |input: usize, output| T::as_from((input + output) % input_domain);
            let many = context
                .parameters()
                .compile_interleaved_lookup_table_fn(count, value)
                .unwrap();
            let singles: Vec<_> = (0..count)
                .map(|output| {
                    context
                        .parameters()
                        .compile_lookup_table_fn(|input| value(input, output))
                        .unwrap()
                })
                .collect();
            let mut outputs = vec![input.clone(); count];
            for message in 0..input_domain {
                let probe = encryptor
                    .encrypt_padded(T::as_from(message), &mut rng)
                    .unwrap();
                evaluator.apply_interleaved_lookup_table_to(&probe, &many, &mut outputs);
                for (index, (single, output)) in singles.iter().zip(&mut outputs).enumerate() {
                    let expected = value(message, index);
                    assert_eq!(decryptor.decrypt(output).unwrap(), expected);
                    evaluator.apply_lookup_table_to(&probe, single, output);
                    assert_eq!(decryptor.decrypt(output).unwrap(), expected);
                }
            }

            for shared in [false, true] {
                let kind = if shared { "many" } else { "separate" };
                group.bench_function(format!("complete_pbs_{kind}_{count}_reused_outputs"), |b| {
                    b.iter(|| {
                        if shared {
                            evaluator.apply_interleaved_lookup_table_to(
                                black_box(&input),
                                black_box(&many),
                                black_box(&mut outputs),
                            );
                        } else {
                            for (table, output) in singles.iter().zip(&mut outputs) {
                                evaluator.apply_lookup_table_to(
                                    black_box(&input),
                                    black_box(table),
                                    black_box(output),
                                );
                            }
                        }
                        black_box(&outputs);
                    });
                });
            }
        }
    }
    group.finish();
}

fn bench_pbs(c: &mut Criterion) {
    for workload in PBS_WORKLOADS {
        for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
            bench_order::<u32, RustFftTable>(c, order, "rustfft", workload);
            bench_order::<u32, TfheFftTable>(c, order, "tfhe", workload);
            bench_order::<u64, RustFftTable>(c, order, "rustfft", workload);
            bench_order::<u64, TfheFftTable>(c, order, "tfhe", workload);
        }
    }
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
