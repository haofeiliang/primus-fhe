//! PBS stages and complete evaluations with precomputed keys and reusable scratch.
//! Outputs and scratch are reused; setup is not timed.
//! Boolean and 2+2 bit workloads; see primus_tfhe/BENCHMARKS.md.
//!
//! cargo bench -p primus_tfhe_glwe_ntt --bench pbs

use primus_test_allocations::{CountingAllocator, measure};
use primus_tfhe_test_support::benchmark::{NTT_Q32, NTT_Q64, PBS_WORKLOADS, PbsWorkload};
use std::hint::black_box;
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingContext};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_glwe_ntt::{
    BooleanGate, BootstrappingKey, NttGlweBlindRotationContext, PbsOrder, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

mod support;
use support::parameters_with_order;

fn order_name(order: PbsOrder) -> &'static str {
    match order {
        PbsOrder::BootstrapKeyswitch => "pbs_ks",
        PbsOrder::KeyswitchBootstrap => "ks_pbs",
    }
}

fn bench_order<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    c: &mut Criterion,
    order: PbsOrder,
    q: T,
    workload: PbsWorkload,
) {
    let parameters = parameters_with_order(order, q, workload);
    let modulus = parameters.accumulator_glwe().cipher_modulus();
    let poly_length = parameters.accumulator_glwe().poly_length();
    let table = Table::new(poly_length.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let ((client_key, server_key), keys) =
        measure(|| context.try_generate_keys(None, &mut rng).unwrap());
    let BootstrappingKey::Classic(bootstrapping_key) = server_key.bootstrapping_key() else {
        panic!("classic benchmark requires a classic server key");
    };
    let parameters = context.parameters();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input_domain = workload.plaintext_modulus as usize / 2;
    let input = encryptor.encrypt_padded(T::ONE, &mut rng).unwrap();
    let lookup_table = context
        .parameters()
        .compile_lookup_table_fn(|x| T::as_from((x + input_domain - 1) % (input_domain)))
        .unwrap();
    let (mut evaluator, scratch) = measure(|| context.evaluator(&server_key).unwrap());
    eprintln!(
        "GLWE/{}/u{}/{:?}: client+server heap={} B, evaluator heap={} B",
        workload.name,
        T::BITS,
        order,
        keys.allocated_bytes - keys.released_bytes,
        scratch.allocated_bytes - scratch.released_bytes
    );
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

    let mut blind_rotation = NttGlweBlindRotationContext::new(bootstrapping_key);
    let mut key_switching = NttGlweKeySwitchingContext::new(
        parameters.glwe_key_switching().output().size().glwe_size(),
    );
    let mut main_glwe: GlweCiphertext<Vec<T>> =
        GlweCiphertext::zero(parameters.accumulator_glwe().glwe_len());
    let mut switched: GlweCiphertext<Vec<T>> =
        GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
    let mut small_lwe: LweCiphertext<T> = LweCiphertext::zero(parameters.small_lwe().dimension());

    match order {
        PbsOrder::BootstrapKeyswitch => bootstrapping_key.ntt_blind_rotate_lookup_table_to(
            &input,
            lookup_table.polynomial(),
            &mut main_glwe,
            modulus,
            context.table(),
            &mut blind_rotation,
        ),
        PbsOrder::KeyswitchBootstrap => {
            input.inverse_extract_glwe_to(&mut main_glwe, poly_length, modulus)
        }
    }
    server_key.glwe_key_switching_key().key_switch_to(
        &main_glwe,
        &mut switched,
        modulus,
        context.table(),
        &mut key_switching,
    );
    switched.extract_compact_lwe_to(&mut small_lwe, poly_length, modulus);

    let glwe_dimension = parameters.accumulator_glwe().dimension();
    let mut group = c.benchmark_group(format!(
        "glwe_ntt/{}/u{}/{}/n{}_N{poly_length}_k{glwe_dimension}",
        workload.name,
        T::BITS,
        order_name(order),
        parameters.small_lwe().dimension(),
    ));
    group.sample_size(20);

    group.bench_function("glwe_key_switching", |b| {
        b.iter(|| {
            server_key.glwe_key_switching_key().key_switch_to(
                black_box(&main_glwe),
                black_box(&mut switched),
                modulus,
                context.table(),
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
            black_box(bootstrapping_key).ntt_blind_rotate_lookup_table_to(
                black_box(blind_rotation_input),
                black_box(lookup_table.polynomial()),
                black_box(&mut main_glwe),
                modulus,
                context.table(),
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
            bench_order::<u32, U32NttTable>(c, order, NTT_Q32, workload);
            bench_order::<u64, U64NttTable>(c, order, NTT_Q64, workload);
        }
    }
}

criterion_group! { name = benches; config = Criterion::default().sample_size(20).warm_up_time(std::time::Duration::from_secs(1)).measurement_time(std::time::Duration::from_secs(5)); targets = bench_pbs }
criterion_main!(benches);
