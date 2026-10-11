//! cargo bench -p primus_tfhe_ntru_lut --bench lookup_evaluate -- 'c4_'
//! Defaults measure NTT and RustFFT; add --features tfhe-fft for all three engines.
//! Parameters and storage: guides/development/testing.md#high-precision-lut-benchmarks
//! One iteration evaluates one complete request with retained keys, table and buffers.

#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
mod workloads {
    use std::hint::black_box;

    use criterion::{Criterion, Throughput};
    use primus_tfhe_ntru_lut::experimental;
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    /// Materialize the full random mapping before compilation/timing, as in lookup_create.
    fn random_function(input_chunk_count: usize) -> Vec<u16> {
        let mut rng = StdRng::seed_from_u64(202);
        (0..1usize << (4 * input_chunk_count))
            .map(|_| rng.random())
            .collect()
    }

    /// Exact Q50 selection/rotation followed by Q→q and independent LWE key switching.
    #[cfg(feature = "ntt")]
    fn ntt(c: &mut Criterion) {
        use primus_ntt::U64NttTable;
        use primus_tfhe_ntru_lut::NttHighPrecLutContext;

        for (precision, base_config) in [
            ("low_prec", experimental::NTT_LOW_PREC_LOOKUP_U64),
            ("high_prec", experimental::NTT_HIGH_PREC_LOOKUP_U64),
        ] {
            let mut group = c.benchmark_group(format!("lookup/evaluate/ntt/classic/{precision}"));
            group.sampling_mode(criterion::SamplingMode::Flat);
            group.throughput(Throughput::Elements(1)); // One request returns four chunks.
            for input_chunk_count in [4, 5, 6] {
                let config = primus_tfhe_ntru_lut::HighPrecLutConfig {
                    input_chunk_count,
                    ..base_config
                };
                let context =
                    NttHighPrecLutContext::<u64, U64NttTable, _>::try_from_config(config).unwrap();
                // Server, offline: retain every public polynomial, including any repeated entries.
                let values = random_function(input_chunk_count);
                let table = context
                    .compile_fn(|x: u64| u64::from(values[x as usize]))
                    .unwrap();

                // Client: independent fixed seeds keep keys and inputs separate from the mapping.
                let mut key_rng = StdRng::seed_from_u64(42);
                let (client, server) = context.try_generate_keys(&mut key_rng).unwrap();
                let encryptor = context.encryptor(&client).unwrap();
                let decryptor = context.decryptor(&client).unwrap();
                let mut input_rng = StdRng::seed_from_u64(1042);
                let mut input = encryptor.allocate_input();

                // Server, offline: bind table/key and allocate all reusable evaluation buffers.
                let mut evaluator = context.evaluator(&server, &table).unwrap();
                let mut output = evaluator.allocate_output();
                let input_mask = (values.len() - 1) as u64;
                let measured_input = 0xabcdef & input_mask;
                for x in [input_mask, measured_input] {
                    encryptor.encrypt_to(x, &mut input, &mut input_rng).unwrap();
                    evaluator.evaluate_to(&input, &mut output);
                    assert_eq!(
                        decryptor.decrypt::<u64>(&output).unwrap(),
                        u64::from(values[x as usize])
                    );
                }
                group.bench_function(format!("m16_d3_c{input_chunk_count}_o4/u64"), |b| {
                    b.iter(|| {
                        evaluator.evaluate_to(black_box(&input), &mut output);
                        black_box(output.as_slice());
                    })
                });
                assert_eq!(
                    decryptor.decrypt::<u64>(&output).unwrap(),
                    u64::from(values[measured_input as usize])
                );
            }
            group.finish();
        }
    }

    /// Native-torus evaluation includes this FFT engine's trace/product rounding.
    #[cfg(any(feature = "rustfft", feature = "tfhe-fft"))]
    fn fourier<Table: primus_fft::FftTable>(c: &mut Criterion, engine: &str) {
        use primus_tfhe_ntru_lut::FourierHighPrecLutContext;

        for (precision, base_config) in [
            ("low_prec", experimental::FOURIER_LOW_PREC_LOOKUP_U64),
            ("high_prec", experimental::FOURIER_HIGH_PREC_LOOKUP_U64),
        ] {
            let mut group =
                c.benchmark_group(format!("lookup/evaluate/{engine}/classic/{precision}"));
            group.sampling_mode(criterion::SamplingMode::Flat);
            group.throughput(Throughput::Elements(1)); // One request returns four chunks.
            for input_chunk_count in [4, 5, 6] {
                let config = primus_tfhe_ntru_lut::HighPrecLutConfig {
                    input_chunk_count,
                    ..base_config
                };
                let context =
                    FourierHighPrecLutContext::<u64, Table, _>::try_from_config(config).unwrap();
                // Server, offline: retain every public polynomial, including any repeated entries.
                let values = random_function(input_chunk_count);
                let table = context
                    .compile_fn(|x: u64| u64::from(values[x as usize]))
                    .unwrap();

                // Client: independent fixed seeds keep keys and inputs separate from the mapping.
                let mut key_rng = StdRng::seed_from_u64(42);
                let (client, server) = context.try_generate_keys(&mut key_rng).unwrap();
                let encryptor = context.encryptor(&client).unwrap();
                let decryptor = context.decryptor(&client).unwrap();
                let mut input_rng = StdRng::seed_from_u64(1042);
                let mut input = encryptor.allocate_input();

                // Server, offline: bind table/key and allocate all reusable evaluation buffers.
                let mut evaluator = context.evaluator(&server, &table).unwrap();
                let mut output = evaluator.allocate_output();
                let input_mask = (values.len() - 1) as u64;
                let measured_input = 0xabcdef & input_mask;
                for x in [input_mask, measured_input] {
                    encryptor.encrypt_to(x, &mut input, &mut input_rng).unwrap();
                    evaluator.evaluate_to(&input, &mut output);
                    assert_eq!(
                        decryptor.decrypt::<u64>(&output).unwrap(),
                        u64::from(values[x as usize])
                    );
                }
                group.bench_function(format!("m16_d3_c{input_chunk_count}_o4/u64"), |b| {
                    b.iter(|| {
                        evaluator.evaluate_to(black_box(&input), &mut output);
                        black_box(output.as_slice());
                    })
                });
                assert_eq!(
                    decryptor.decrypt::<u64>(&output).unwrap(),
                    u64::from(values[measured_input as usize])
                );
            }
            group.finish();
        }
    }

    pub(super) fn benchmarks(c: &mut Criterion) {
        #[cfg(feature = "ntt")]
        ntt(c);
        #[cfg(feature = "rustfft")]
        fourier::<primus_fft::RustFftTable>(c, "rustfft");
        #[cfg(feature = "tfhe-fft")]
        fourier::<primus_fft::TfheFftTable>(c, "tfhe-fft");
    }
}

#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default().sample_size(10)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = workloads::benchmarks
}
#[cfg(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft"))]
criterion::criterion_main!(benches);

#[cfg(not(any(feature = "ntt", feature = "rustfft", feature = "tfhe-fft")))]
fn main() {
    panic!("enable ntt, rustfft or tfhe-fft to run lookup evaluation benchmarks");
}
