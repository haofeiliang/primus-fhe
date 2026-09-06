//! cargo bench -p primus_factor --bench shoup_factor
//! cargo +nightly bench -p primus_factor --bench shoup_factor --features simd

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_factor::{FactorSliceOps, ShoupFactor};
use primus_integer::FheUint;
use std::hint::black_box;

fn slices<T: FheUint + TryFrom<u64>>(
    c: &mut Criterion,
    name: &str,
    modulus: T,
    factor: impl FactorSliceOps<T> + Copy,
    q: u64,
) {
    for n in [1024, 1025, 4096] {
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut values = || {
            (0..n)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    T::try_from(state % q)
                        .ok()
                        .expect("value fits the benchmark word")
                })
                .collect::<Vec<T>>()
        };
        let data = values();
        let rhs = values();
        let mut output = data.clone();
        let mut group = c.benchmark_group(format!("factor/shoup/{name}/n{n}"));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function("mul_to", |b| {
            b.iter(|| {
                black_box(factor).factor_mul_slice_to(
                    black_box(&data),
                    black_box(&mut output),
                    black_box(modulus),
                )
            })
        });
        group.bench_function("mul_assign", |b| {
            b.iter(|| {
                black_box(factor)
                    .factor_mul_slice_assign(black_box(&mut output), black_box(modulus))
            })
        });
        group.bench_function("add_mul_assign", |b| {
            b.iter(|| {
                black_box(factor).add_factor_mul_slice_assign(
                    black_box(&mut output),
                    black_box(&rhs),
                    black_box(modulus),
                )
            })
        });
        group.bench_function("sub_mul_assign", |b| {
            b.iter(|| {
                black_box(factor).sub_factor_mul_slice_assign(
                    black_box(&mut output),
                    black_box(&rhs),
                    black_box(modulus),
                )
            })
        });
        group.finish();
    }
}

fn benchmarks(c: &mut Criterion) {
    const Q32: u32 = 132_120_577;
    const Q64: u64 = 1_125_899_906_826_241;
    // Same nontrivial multiplier as modulus scalar benchmarks; construction is
    // excluded so timings represent amortized use of a precomputed factor.
    slices(
        c,
        "u32/q132120577",
        Q32,
        ShoupFactor::new(17, Q32),
        u64::from(Q32),
    );
    slices(
        c,
        "u64/q1125899906826241",
        Q64,
        ShoupFactor::new(17, Q64),
        Q64,
    );
}
criterion_group!(benches, benchmarks);
criterion_main!(benches);
