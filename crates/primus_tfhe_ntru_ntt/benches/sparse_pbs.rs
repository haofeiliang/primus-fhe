//! Same fixed invertible client: classic vs bucket-aggregated complete PBS.
//! Includes initialization, all buckets, return KS and compact extraction. Reuses
//! online outputs/scratch and keygen workspace; key drops are outside timing.
//! Setup checks all eight padded messages and reports retained heap/phase error.
//! Regression parameters, not a matched-security or certified-failure comparison.
//!
//! cargo bench -p primus_tfhe_ntru_ntt --bench sparse_pbs
//! SIMD: cargo +nightly bench -p primus_tfhe_ntru_ntt --bench sparse_pbs --features simd

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_test_allocations::{CountingAllocator, measure};
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, KeyGenerator, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn backend<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion, q: T) {
    const N: usize = 1024;
    const DIMENSION: usize = 728;
    const WEIGHT: usize = 32;
    let modulus = BarrettModulus::new(q);
    let decomposition = DecompositionConfig {
        log_basis: 8,
        level_count: None,
    };
    let parameters = TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            DIMENSION,
            T::as_from(16usize),
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
            0.7,
        ),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: decomposition,
        key_switching: decomposition,
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    let context = TfheContext::<T, Table>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0xB802);
    let mut generator = KeyGenerator::new(&context);
    let client = generator.try_generate_client_key(&mut rng).unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let decryptor = context.decryptor(&client).unwrap();
    let inputs: Vec<_> = (0..8usize)
        .map(|m| encryptor.encrypt_padded(T::as_from(m), &mut rng).unwrap())
        .collect();
    let codec = RoundedCodec::new(T::as_from(8usize), modulus);
    let value = |m: usize, i: usize| T::as_from((m + 2 * i) % 8);
    let single = context
        .parameters()
        .compile_lookup_table_fn(&codec, |m| value(m, 0))
        .unwrap();
    let many = context
        .parameters()
        .compile_interleaved_lookup_table_fn(&codec, 3, value)
        .unwrap();
    for sparse in [false, true] {
        let label = format!(
            "ntru_ntt/u{}/{}",
            T::BITS,
            if sparse {
                "sparse"
            } else {
                "classic_fixed_weight"
            }
        );
        let (server, key_memory) = measure(|| {
            if sparse {
                generator.try_generate_sparse_server_key(&client, 3, 2 * WEIGHT, &mut rng)
            } else {
                generator.try_generate_server_key(&client, None, &mut rng)
            }
            .unwrap()
        });
        let (mut evaluator, scratch) = measure(|| context.evaluator(&server).unwrap());
        let mut output = inputs[0].clone();
        let mut outputs = vec![output.clone(); 3];
        let mut max_error = [0.0f64; 2];
        for (message, input) in inputs.iter().enumerate() {
            for count in [1, 3] {
                let (_, allocations) = measure(|| {
                    if count == 1 {
                        evaluator.apply_lookup_table_to(input, &single, &mut output);
                    } else {
                        evaluator.apply_interleaved_lookup_table_to(input, &many, &mut outputs);
                    }
                });
                assert_eq!(allocations.count, 0);
                let results = if count == 1 {
                    std::slice::from_ref(&output)
                } else {
                    &outputs
                };
                for (i, cipher) in results.iter().enumerate() {
                    let phase = decryptor.decrypt_phase(cipher).unwrap();
                    assert_eq!(codec.decode_value(phase), value(message, i));
                    let encoded =
                        codec.encode_value(value(message, i), PlaintextEmbedding::Unsigned);
                    let difference = if phase >= encoded {
                        phase - encoded
                    } else {
                        encoded - phase
                    };
                    let error: f64 = difference.min(q - difference).as_into();
                    let q_float: f64 = q.as_into();
                    let index = usize::from(count == 3);
                    max_error[index] = max_error[index].max(error / q_float);
                }
            }
        }
        eprintln!(
            "{label}: server heap={} B, evaluator heap={} B, max phase error/q single={:.6e}, many3={:.6e}",
            key_memory.allocated_bytes - key_memory.released_bytes,
            scratch.allocated_bytes - scratch.released_bytes,
            max_error[0],
            max_error[1]
        );
        // Criterion's adaptive iteration count must not change later setup keys.
        let mut keygen_rng = StdRng::seed_from_u64(0xB80201);
        c.bench_function(&format!("{label}/server_keygen"), |b| {
            b.iter_batched(
                || (),
                |_| {
                    if sparse {
                        generator.try_generate_sparse_server_key(
                            &client,
                            3,
                            2 * WEIGHT,
                            &mut keygen_rng,
                        )
                    } else {
                        generator.try_generate_server_key(&client, None, &mut keygen_rng)
                    }
                    .unwrap()
                },
                BatchSize::PerIteration,
            );
        });
        for count in [1, 3] {
            c.bench_function(&format!("{label}/complete_pbs_{count}"), |b| {
                let mut cursor = 0;
                b.iter(|| {
                    let input = black_box(&inputs[cursor]);
                    if count == 1 {
                        evaluator.apply_lookup_table_to(
                            input,
                            black_box(&single),
                            black_box(&mut output),
                        );
                    } else {
                        evaluator.apply_interleaved_lookup_table_to(
                            input,
                            black_box(&many),
                            black_box(&mut outputs),
                        );
                    }
                    cursor = (cursor + 1) % inputs.len();
                });
            });
        }
    }
}

fn sparse_pbs(c: &mut Criterion) {
    backend::<_, U32NttTable>(c, 132_120_577);
    backend::<_, U64NttTable>(c, 1_125_899_906_826_241);
}

criterion_group!(benches, sparse_pbs);
criterion_main!(benches);
