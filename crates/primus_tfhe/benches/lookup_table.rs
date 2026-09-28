//! Compile and drop one owned raw-output LUT per iteration. Encoding geometry,
//! validation, allocation and coefficient filling are timed; modulus setup is not.
//! N=1024; u32/u64 and Native/PowOf2/Barrett arithmetic. Three geometries
//! isolate one output, padded interleaving and the near-capacity narrow cells.
//!
//! cargo bench -p primus_tfhe --bench lookup_table

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_integer::FheUint;
use primus_modulus::{BarrettModulus, NativeModulus, PowOf2Modulus};
use primus_reduce::RingContext;
use primus_tfhe::{InterleavedLookupTable, LookupTable};

fn compile<T, M>(c: &mut Criterion, name: &str, modulus: M)
where
    T: FheUint,
    M: RingContext<T>,
{
    const N: usize = 1024;
    let mut group = c.benchmark_group(format!("lut_compile/u{}/{name}/N{N}", T::BITS));
    for (t, output_count) in [(32u32, 1), (16, 3), (255, 4)] {
        let input_domain_len = t.div_ceil(2) as usize;
        let id = BenchmarkId::new(format!("t{t}"), format!("k{output_count}"));
        if output_count == 1 {
            group.bench_function(id, |b| {
                b.iter(|| {
                    black_box(
                        LookupTable::try_new(
                            black_box(input_domain_len),
                            black_box(N),
                            black_box(T::as_from(t)),
                            modulus,
                            modulus,
                            |input| Ok(T::as_from(13 * input)),
                        )
                        .unwrap(),
                    )
                });
            });
        } else {
            group.bench_function(id, |b| {
                b.iter(|| {
                    black_box(
                        InterleavedLookupTable::try_new(
                            black_box(input_domain_len),
                            black_box(N),
                            black_box(output_count),
                            black_box(T::as_from(t)),
                            modulus,
                            modulus,
                            |input, output| Ok(T::as_from(13 * input + output)),
                        )
                        .unwrap(),
                    )
                });
            });
        }
    }
    group.finish();
}

fn lookup_table(c: &mut Criterion) {
    compile(c, "native", NativeModulus::<u32>::new());
    compile(c, "native", NativeModulus::<u64>::new());
    compile(c, "pow2_q24", PowOf2Modulus::<u32>::new(1 << 24));
    compile(c, "pow2_q24", PowOf2Modulus::<u64>::new(1 << 24));
    compile(c, "barrett_q27", BarrettModulus::new(132_120_577u32));
    compile(
        c,
        "barrett_q50",
        BarrettModulus::new(1_125_899_906_826_241u64),
    );
}

criterion_group!(benches, lookup_table);
criterion_main!(benches);
