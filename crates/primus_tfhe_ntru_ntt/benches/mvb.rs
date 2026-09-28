//! Produce k threshold bits from one encrypted input. D8/k3 compares independent
//! PBS, interleaved ManyLUT and factorized MVB; D64/k17 exceeds interleaved
//! capacity. One iteration produces all k outputs, with no setup or allocation.
//! Sparse NTRU supports independent/interleaved PBS, but not factorized MVB.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_ntt --bench mvb

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use criterion::{SamplingMode, Throughput};
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_tfhe_ntru_ntt::{InterleavedLookupTable, KeyGenerator, LookupTable, TfheContext};
use primus_tfhe_test_support::parameters::ntru;
use primus_tfhe_test_support::parameters::ntt_modulus;
use rand::{SeedableRng, rngs::StdRng};

// Register only meaningful comparisons, not every Cartesian product of shapes.
// A cached key fixture is shared by algorithms; LUT/workspace construction is
// local to the selected algorithm and stays outside b.iter.
fn backend<T: FheUint, Table: MonomialNttTable<ValueT = T>>(c: &mut Criterion, backend: &str) {
    for (domain, count) in [(8usize, 3usize), (64, 17)] {
        for sparse in [false, true] {
            if sparse && domain == 64 {
                continue;
            }
            let kind = if sparse { "sparse" } else { "classic" };
            let parameters = ntru::diagnostic(ntt_modulus::<T>(), (2 * domain) as u32);
            let mut fixture = None;
            let mut group = c.benchmark_group(format!(
                "ntru/{backend}/u{}/mvb/{kind}/n728_h32_N1024/D{domain}_k{count}",
                T::BITS
            ));
            group.sampling_mode(SamplingMode::Flat);
            group.throughput(Throughput::Elements(count as u64));
            for path in ["independent", "interleaved", "factorized"] {
                if path == "interleaved" && domain == 64 {
                    continue;
                }
                if sparse && path == "factorized" {
                    continue;
                }
                let mut verified = false;
                group.bench_function(path, |b| {
                    let (context, client, server, input) = fixture.get_or_insert_with(|| {
                        let context =
                            TfheContext::<T, Table, PowOf2Modulus<T>>::try_from_parameters(
                                parameters.clone(),
                            )
                            .unwrap();
                        let mut rng = StdRng::seed_from_u64(42);
                        let mut generator = KeyGenerator::new(&context);
                        let client = generator.try_generate_client_key(&mut rng).unwrap();
                        let server = if sparse {
                            generator
                                .try_generate_sparse_server_key(&client, 3, 64, &mut rng)
                                .unwrap()
                        } else {
                            generator
                                .try_generate_server_key(&client, None, &mut rng)
                                .unwrap()
                        };
                        let input = context
                            .encryptor(&client)
                            .unwrap()
                            .encrypt_padded(T::as_from(domain / 2), &mut rng)
                            .unwrap();
                        (context, client, server, input)
                    });
                    let value = |m: usize, i: usize| {
                        if m >= (i + 1) * domain / (count + 1) {
                            T::ONE
                        } else {
                            T::ZERO
                        }
                    };
                    // Public tables live in the ring modulus; returned phases
                    // must be decoded in the external LWE modulus (q != Q for NTRU).
                    let table_codec = ScaledCodec::new(
                        T::TWO,
                        context.parameters().accumulator_ntru().cipher_modulus(),
                    );
                    let output_codec = ScaledCodec::new(
                        T::TWO,
                        context.parameters().external_lwe().cipher_modulus(),
                    );
                    let mut outputs: Vec<_> = (0..count)
                        .map(|_| context.allocate_lwe_ciphertext())
                        .collect();
                    // Branch once during setup; the measured closure has no path dispatch.
                    let mut check = |outputs: &[_]| {
                        if !verified {
                            let decryptor = context.decryptor(client).unwrap();
                            for (i, output) in outputs.iter().enumerate() {
                                assert_eq!(
                                    output_codec
                                        .decode_value(decryptor.decrypt_phase(output).unwrap()),
                                    value(domain / 2, i)
                                );
                            }
                            verified = true;
                        }
                    };
                    match path {
                        "independent" => {
                            let luts: Vec<_> = (0..count)
                                .map(|i| {
                                    LookupTable::try_new(
                                        domain,
                                        1024,
                                        T::as_from(2 * domain),
                                        output_codec.ciphertext_modulus(),
                                        table_codec.ciphertext_modulus(),
                                        |m| {
                                            Ok(table_codec.encode_value(
                                                value(m, i),
                                                PlaintextEmbedding::Unsigned,
                                            ))
                                        },
                                    )
                                    .unwrap()
                                })
                                .collect();
                            let mut evaluator = context.evaluator(server).unwrap();
                            let mut run = |outputs: &mut [_]| {
                                for (lut, output) in luts.iter().zip(outputs) {
                                    evaluator.apply_lookup_table_to(
                                        black_box(input),
                                        black_box(lut),
                                        output,
                                    );
                                }
                            };
                            run(&mut outputs);
                            check(&outputs);
                            b.iter(|| run(black_box(&mut outputs)));
                        }
                        "interleaved" => {
                            let lut = InterleavedLookupTable::try_new(
                                domain,
                                1024,
                                count,
                                T::as_from(2 * domain),
                                output_codec.ciphertext_modulus(),
                                table_codec.ciphertext_modulus(),
                                |m, i| {
                                    Ok(table_codec
                                        .encode_value(value(m, i), PlaintextEmbedding::Unsigned))
                                },
                            )
                            .unwrap();
                            let mut evaluator = context.evaluator(server).unwrap();
                            evaluator.apply_interleaved_lookup_table_to(input, &lut, &mut outputs);
                            check(&outputs);
                            b.iter(|| {
                                evaluator.apply_interleaved_lookup_table_to(
                                    black_box(input),
                                    black_box(&lut),
                                    black_box(&mut outputs),
                                )
                            });
                        }
                        "factorized" => {
                            let lut = context
                                .compile_factorized_lookup_table_fn(
                                    &table_codec,
                                    domain,
                                    count,
                                    value,
                                )
                                .unwrap();
                            let mut evaluator = context.factorized_evaluator(server).unwrap();
                            evaluator.apply_lookup_table_to(input, &lut, &mut outputs);
                            check(&outputs);
                            b.iter(|| {
                                evaluator.apply_lookup_table_to(
                                    black_box(input),
                                    black_box(&lut),
                                    black_box(&mut outputs),
                                )
                            });
                        }
                        _ => unreachable!(),
                    }
                });
            }
            group.finish();
        }
    }
}

fn bench_mvb(c: &mut Criterion) {
    backend::<u32, U32NttTable>(c, "ntt");
    backend::<u64, U64NttTable>(c, "ntt");
}

criterion_group!(benches, bench_mvb);
criterion_main!(benches);
