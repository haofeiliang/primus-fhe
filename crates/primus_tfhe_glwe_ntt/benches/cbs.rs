//! cargo bench -p primus_tfhe_glwe_ntt --bench cbs
//! Parameters and comparison limits: guides/development/testing.md#tfhe-benchmarks
//! One iteration is one server request. Setup and correctness checks are untimed.

use criterion::{Criterion, Throughput};
use primus_ntt::U64NttTable as Table;
use primus_tfhe_glwe_ntt::{TfheContext, experimental};
use rand::{SeedableRng, rngs::StdRng};
use std::hint::black_box;

type Word = u64;

fn benchmark(c: &mut Criterion) {
    let engine = "ntt";
    let config = experimental::CLASSIC_CBS_U64;
    let context = TfheContext::<Word, Table>::try_from_cbs_config(config).unwrap();
    // Client: keys, inputs and candidate ciphertexts are all prepared outside timing.
    let mut rng = StdRng::seed_from_u64(42);
    let (client, server) = context
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let encryptor = context.encryptor(client.external_lwe_secret_key()).unwrap();
    let mut input = context.allocate_lwe_ciphertext();
    let n = config.pbs.bsk_poly_length.get();
    let mut ring_client = context
        .accumulator_client(client.glwe_secret_key(), 8)
        .unwrap();
    let messages: Vec<Vec<Word>> = (0..2)
        .map(|r| (0..n).map(|i| ((i * (r + 1) + r) % 4) as Word).collect())
        .collect();
    let candidates: Vec<_> = messages
        .iter()
        .map(|m| ring_client.encrypt(m, &mut rng))
        .collect();
    let mut decoded = vec![0; n];

    // Server: time selector construction and its actual consumption, not ring decryption.
    let mut selected = context.allocate_accumulator_ciphertext();
    let program = context.compile_cbs_fn(|m| Word::from(m >= 2)).unwrap();
    let mut evaluator = context
        .circuit_bootstrap_evaluator_with_lookup_table(&server, program)
        .unwrap();
    let mut control = evaluator.allocate_output();
    for message in [1, 3] {
        encryptor
            .encrypt_padded_to(message, input.as_mut_view(), &mut rng)
            .unwrap();
        evaluator.circuit_bootstrap_to(input.as_view(), control.as_mut_view());
        evaluator.cmux_to(
            control.as_view(),
            candidates[0].as_view(),
            candidates[1].as_view(),
            selected.as_mut_view(),
        );
        ring_client.decrypt_to(&selected, &mut decoded);
        assert_eq!(decoded, messages[usize::from(message >= 2)]);
    }
    let mut group = c.benchmark_group(format!("cbs/glwe/{engine}"));
    group.throughput(Throughput::Elements(1)); // Complete requests, not output count.
    group.bench_function("predicate_cmux/u64", |b| {
        b.iter(|| {
            evaluator.circuit_bootstrap_to(black_box(input.as_view()), control.as_mut_view());
            evaluator.cmux_to(
                control.as_view(),
                candidates[0].as_view(),
                candidates[1].as_view(),
                selected.as_mut_view(),
            );
            black_box(selected.as_view());
        })
    });
    group.finish();
    ring_client.decrypt_to(&selected, &mut decoded);
    assert_eq!(decoded, messages[1]);
}

fn benchmarks(c: &mut Criterion) {
    benchmark(c);
}

criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default().sample_size(20)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = benchmarks
}
criterion::criterion_main!(benches);
