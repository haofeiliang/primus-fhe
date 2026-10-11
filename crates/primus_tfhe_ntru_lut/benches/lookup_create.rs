//! cargo bench -p primus_tfhe_ntru_lut --bench lookup_create -- 'c4_'
//! Also works with --no-default-features: public compilation needs no transform.
//! Parameters and storage: guides/development/testing.md#high-precision-lut-benchmarks
//! One iteration creates and drops one complete LUT; the random function is prepared once.

use std::hint::black_box;

use criterion::{Criterion, Throughput};
use primus_encoding::RoundedCodec;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use primus_shape::PolyLength;
use primus_tfhe_ntru_lut::{HighPrecisionLookupTable, LookupTableConfig};
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// The same complete 16-bit random mapping is used by lookup_evaluate.
/// Independent output digits may repeat; the fixture never rejects duplicates.
fn random_function(input_chunk_count: usize) -> Vec<u16> {
    let mut rng = StdRng::seed_from_u64(202);
    (0..1usize << (4 * input_chunk_count))
        .map(|_| rng.random())
        .collect()
}

/// Q changes coefficient encoding, while both FFT engines share NativeModulus.
/// Measure allocation, enumeration, encoding, full storage and drop together.
fn benchmark<M: RingContext<u64>>(c: &mut Criterion, ring_modulus: M, name: &str) {
    let poly_length = PolyLength::new(4096);
    let input_codec = RoundedCodec::try_new(32, PowOf2Modulus::new(1 << 24)).unwrap();
    let mut group = c.benchmark_group(format!("lookup/create_and_drop/{name}"));
    group.sampling_mode(criterion::SamplingMode::Flat);
    group.throughput(Throughput::Elements(1)); // Complete tables, not coefficients.
    for input_chunk_count in [4, 5, 6] {
        let values = random_function(input_chunk_count);
        let config = LookupTableConfig {
            input_chunk_count,
            output_chunk_count: 4,
            coefficient_chunk_count: 3,
        };
        group.bench_function(format!("m16_d3_c{input_chunk_count}_o4/u64"), |b| {
            b.iter(|| {
                let values = black_box(values.as_slice());
                black_box(
                    HighPrecisionLookupTable::try_new(
                        poly_length,
                        ring_modulus,
                        &input_codec,
                        config,
                        |x, output| u64::from((values[x] >> (4 * output)) & 15),
                    )
                    .unwrap(),
                )
            })
        });
    }
    group.finish();
}

fn benchmarks(c: &mut Criterion) {
    benchmark(c, BarrettModulus::new(1_125_899_906_826_241), "q50");
    benchmark(c, NativeModulus::<u64>::new(), "native64");
}

criterion::criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets = benchmarks
}
criterion::criterion_main!(benches);
