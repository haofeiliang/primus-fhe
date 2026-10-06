//! Produce k threshold bits from one encrypted input. D8/k3 compares independent
//! PBS, interleaved ManyLUT and factorized MVB; D64/k17 exceeds interleaved
//! capacity. One iteration produces all k outputs, with no setup or allocation.
//! D8/k3 pairs classic/sparse for all three paths; D64/k17 keeps classic only.
//! Parameters: primus_tfhe_test_support::parameters (arithmetic cost profiles).
//! Fixtures are initialized only for selected IDs, then reused across samples.
//! Run: cargo bench -p primus_tfhe_ntru_fourier --bench mvb

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use criterion::{SamplingMode, Throughput};
use primus_encoding::RoundedCodec;
use primus_encoding::{PlaintextEmbedding, ScaledCodec};
#[cfg(feature = "rustfft")]
use primus_fft::RustFftTable;
#[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
use primus_fft::TfheFftTable;
use primus_fft::{FftTable, TorusFftValue};
use primus_lwe::LweCiphertext;
use primus_modulus::NativeModulus;
use primus_modulus::PowOf2Modulus;
use primus_tfhe_ntru_fourier::{
    BlindRotationConfig, InterleavedLookupTable, KeyGenerator, LookupTable, TfheContext,
};
use primus_tfhe_test_support::parameters::ntru;
use rand::{SeedableRng, rngs::StdRng};

// Register only meaningful comparisons, not every Cartesian product of shapes.
// A cached key fixture is shared by algorithms; LUT/workspace construction is
// local to the selected algorithm and stays outside b.iter.
fn backend<T: TorusFftValue, Table: FftTable>(c: &mut Criterion, backend: &str) {
    for (domain, count, sparse) in [(8usize, 3usize, false), (8, 3, true), (64, 17, false)] {
        let kind = if sparse { "sparse" } else { "classic" };
        let parameters = ntru::diagnostic(NativeModulus::<T>::new());
        let input_codec = RoundedCodec::new(
            T::as_from((2 * domain) as u32),
            parameters.external_lwe().cipher_modulus(),
        );
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
            let mut verified = false;
            group.bench_function(path, |b| {
                let (context, client, server, input) = fixture.get_or_insert_with(|| {
                    let context = TfheContext::<T, Table, PowOf2Modulus<T>>::from_parameters(
                        parameters.clone(),
                    );
                    let mut rng = StdRng::seed_from_u64(42);
                    let mut generator = KeyGenerator::new(&context);
                    let client = generator.try_generate_client_key(&mut rng).unwrap();
                    let blind_rotation = if sparse {
                        BlindRotationConfig::Sparse {
                            copy_count: 3,
                            bucket_count: 64,
                        }
                    } else {
                        BlindRotationConfig::Classic
                    };
                    let server = generator
                        .try_generate_server_key(&client, blind_rotation, None, &mut rng)
                        .unwrap();
                    let input = context
                        .encryptor(client.external_lwe_secret_key(), &input_codec)
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
                let output_codec =
                    ScaledCodec::new(T::TWO, context.parameters().external_lwe().cipher_modulus());
                let mut outputs: Vec<_> = (0..count)
                    .map(|_| context.allocate_lwe_ciphertext())
                    .collect();
                // Branch once during setup; the measured closure has no path dispatch.
                let mut check = |outputs: &[LweCiphertext<T>]| {
                    if !verified {
                        let decryptor = context
                            .decryptor(client.external_lwe_secret_key(), &input_codec)
                            .unwrap();
                        for (i, output) in outputs.iter().enumerate() {
                            assert_eq!(
                                output_codec.decode_value(
                                    decryptor.decrypt_phase(output.as_view()).unwrap()
                                ),
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
                                    context.parameters().accumulator_ntru().poly_length(),
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
                        let mut run = |outputs: &mut [LweCiphertext<T>]| {
                            for (lut, output) in luts.iter().zip(outputs) {
                                evaluator.apply_lookup_table_to(
                                    black_box(input.as_view()),
                                    black_box(lut),
                                    output.as_mut_view(),
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
                            context.parameters().accumulator_ntru().poly_length(),
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
                        evaluator.apply_interleaved_lookup_table_to(
                            input.as_view(),
                            &lut,
                            &mut outputs,
                        );
                        check(&outputs);
                        b.iter(|| {
                            evaluator.apply_interleaved_lookup_table_to(
                                black_box(input.as_view()),
                                black_box(&lut),
                                black_box(&mut outputs),
                            )
                        });
                    }
                    "factorized" => {
                        let lut = context
                            .compile_factorized_lookup_table_fn(
                                &input_codec,
                                &table_codec,
                                domain,
                                count,
                                value,
                            )
                            .unwrap();
                        let mut pbs = context.evaluator(server).unwrap();
                        let mut evaluator =
                            primus_tfhe_ntru_fourier::FactorizedEvaluator::new(&pbs);
                        evaluator.apply_lookup_table_to(
                            input.as_view(),
                            &lut,
                            &mut outputs,
                            &mut pbs,
                        );
                        check(&outputs);
                        b.iter(|| {
                            evaluator.apply_lookup_table_to(
                                black_box(input.as_view()),
                                black_box(&lut),
                                black_box(&mut outputs),
                                &mut pbs,
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

fn bench_mvb(c: &mut Criterion) {
    #[cfg(feature = "rustfft")]
    {
        backend::<u64, RustFftTable>(c, "rustfft");
    }
    #[cfg(all(not(feature = "rustfft"), feature = "tfhe-fft"))]
    {
        backend::<u64, TfheFftTable>(c, "tfhe_fft");
    }
}

criterion_group!(benches, bench_mvb);
criterion_main!(benches);
