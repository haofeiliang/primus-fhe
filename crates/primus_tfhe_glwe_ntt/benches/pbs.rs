//! PBS stages and complete evaluations with precomputed keys and reusable scratch.
//! Allocating and reused-output cases are named separately; setup is not timed.
//! Uses `boolean_parameters()` with a fixed seed; these are regression workloads.
//!
//! cargo bench -p primus_tfhe_glwe_ntt --bench pbs

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingContext};
use primus_lwe::LweCiphertext;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    BooleanGate, NttGlweBlindRotationContext, PbsOrder, TfheContext, TfheParameters,
    boolean_parameters,
};
use rand::{SeedableRng, rngs::StdRng};

fn parameters_with_order(order: PbsOrder) -> TfheParameters<u32> {
    let parameters = boolean_parameters();
    TfheParameters::try_new(
        parameters.small_lwe().clone(),
        parameters.glwe().clone(),
        parameters.bootstrapping().basis().clone(),
        parameters.glwe_key_switching().output().basis().clone(),
        order,
    )
    .unwrap()
}

fn order_name(order: PbsOrder) -> &'static str {
    match order {
        PbsOrder::BootstrapKeyswitch => "bootstrap_keyswitch",
        PbsOrder::KeyswitchBootstrap => "keyswitch_bootstrap",
    }
}

fn bench_order(c: &mut Criterion, order: PbsOrder) {
    let parameters = parameters_with_order(order);
    let modulus = parameters.glwe().cipher_modulus();
    let poly_length = parameters.glwe().poly_length();
    let table = U32NttTable::new(poly_length.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let parameters = context.parameters();
    let encryptor = context.encryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(1u32, &mut rng).unwrap();
    let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = input.clone();

    let mut blind_rotation = NttGlweBlindRotationContext::new(parameters.bootstrapping().size());
    let mut key_switching = NttGlweKeySwitchingContext::new(
        parameters.glwe_key_switching().output().size().glwe_size(),
    );
    let mut main_glwe: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.glwe().glwe_len());
    let mut switched: GlweCiphertext<Vec<u32>> =
        GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len());
    let mut small_lwe: LweCiphertext<u32> = LweCiphertext::zero(parameters.small_lwe().dimension());
    let mut external_lwe: LweCiphertext<u32> =
        LweCiphertext::zero(parameters.ciphertext_lwe_dimension());

    match order {
        PbsOrder::BootstrapKeyswitch => server_key
            .bootstrapping_key()
            .ntt_blind_rotate_lookup_table_to(
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

    let boolean_encryptor = context.boolean_encryptor(&client_key).unwrap();
    let boolean_lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let boolean_rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let mut boolean_output = boolean_lhs.clone();
    let mut boolean_evaluator = context.boolean_evaluator(&server_key).unwrap();

    let glwe_dimension = parameters.glwe().dimension();
    let mut group = c.benchmark_group(format!(
        "tfhe_pbs/ntt/u32/{}/n{poly_length}/k{glwe_dimension}/small_lwe{}/external_lwe{}",
        order_name(order),
        parameters.small_lwe().dimension(),
        parameters.ciphertext_lwe_dimension(),
    ));
    group.sample_size(10);

    if order == PbsOrder::KeyswitchBootstrap {
        group.bench_function("inverse_sample_extraction", |b| {
            b.iter(|| {
                input.inverse_extract_glwe_to(black_box(&mut main_glwe), poly_length, modulus);
                black_box(&main_glwe);
            });
        });
    }

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
    group.bench_function("compact_sample_extraction", |b| {
        b.iter(|| {
            switched.extract_compact_lwe_to(black_box(&mut small_lwe), poly_length, modulus);
            black_box(&small_lwe);
        });
    });
    group.bench_function("blind_rotation", |b| {
        let blind_rotation_input = match order {
            PbsOrder::BootstrapKeyswitch => &input,
            PbsOrder::KeyswitchBootstrap => &small_lwe,
        };
        b.iter(|| {
            black_box(server_key.bootstrapping_key()).ntt_blind_rotate_lookup_table_to(
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
    if order == PbsOrder::KeyswitchBootstrap {
        group.bench_function("full_sample_extraction", |b| {
            b.iter(|| {
                main_glwe.extract_lwe_to(black_box(&mut external_lwe), poly_length, modulus);
                black_box(&external_lwe);
            });
        });
    }

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
    group.bench_function("complete_pbs_allocating", |b| {
        b.iter(|| {
            black_box(evaluator.apply_lookup_table(black_box(&input), black_box(&lookup_table)));
        });
    });
    group.bench_function("boolean_and_allocating", |b| {
        b.iter(|| {
            black_box(boolean_evaluator.and(black_box(&boolean_lhs), black_box(&boolean_rhs)))
        });
    });
    group.bench_function("boolean_mux_allocating", |b| {
        b.iter(|| {
            black_box(boolean_evaluator.mux(
                black_box(&boolean_lhs),
                black_box(&boolean_lhs),
                black_box(&boolean_rhs),
            ))
        });
    });
    // One representative per binary input path: add, and subtract-then-double.
    for gate in [BooleanGate::And, BooleanGate::Xor] {
        group.bench_function(format!("boolean_{gate:?}").to_lowercase(), |b| {
            b.iter(|| {
                boolean_evaluator.evaluate_binary_to(
                    gate,
                    black_box(&boolean_lhs),
                    black_box(&boolean_rhs),
                    black_box(&mut boolean_output),
                );
                black_box(&boolean_output);
            });
        });
    }
    group.bench_function("boolean_not", |b| {
        b.iter(|| {
            boolean_evaluator.not_to(black_box(&boolean_lhs), black_box(&mut boolean_output));
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
    // Each iteration produces the same 2/4 function outputs. Compare shared
    // BR/KS against separate PBS calls; all tables, keys and outputs are reused.
    for count in [2, 4] {
        let value = |input: usize, output| ((input + output) % 4) as u32;
        let many = context.compile_many_lookup_table_fn(count, value).unwrap();
        let singles: Vec<_> = (0..count)
            .map(|output| {
                context
                    .compile_lookup_table_fn(|input| value(input, output))
                    .unwrap()
            })
            .collect();
        group.bench_function(format!("complete_pbs_many_{count}_allocating"), |b| {
            b.iter(|| {
                black_box(evaluator.apply_many_lookup_table(black_box(&input), black_box(&many)))
            });
        });
        let mut outputs = vec![input.clone(); count];
        for shared in [false, true] {
            let kind = if shared { "many" } else { "separate" };
            group.bench_function(format!("complete_pbs_{kind}_{count}_reused_outputs"), |b| {
                b.iter(|| {
                    if shared {
                        evaluator.apply_many_lookup_table_to(
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
    group.finish();
}

fn bench_pbs(c: &mut Criterion) {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        bench_order(c, order);
    }
}

criterion_group!(benches, bench_pbs);
criterion_main!(benches);
