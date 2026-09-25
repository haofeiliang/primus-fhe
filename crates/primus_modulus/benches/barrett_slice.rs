//! Run with `cargo bench -p primus_modulus --bench barrett_slice`.
//!
//! To benchmark the SIMD implementation, run
//! `cargo +nightly bench -p primus_modulus --bench barrett_slice --features simd`.

#[path = "support/slice.rs"]
mod slice_support;
mod support;

use core::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_modulus::{BarrettModulus, UintModulus};
use primus_reduce::prelude::*;
use slice_support::{
    MODULUS_U32, MODULUS_U64, POLY_LENGTH, SCALING_LENGTHS, bench_binary_to, bench_dot_product,
};
use support::{benchmark_config, inputs};

fn bench_barrett_u32(c: &mut Criterion) {
    let input = inputs(MODULUS_U32, POLY_LENGTH);
    let len = input.lhs.len();
    let modulus = BarrettModulus::new(MODULUS_U32);

    let mut canonical = vec![0; len];
    let mut lazy = vec![0; len];
    modulus.reduce_mul_slice_to(&input.lhs, &input.rhs, &mut canonical);
    modulus.lazy_reduce_mul_slice_to(&input.lhs, &input.rhs, &mut lazy);
    modulus.reduce_once_slice_assign(&mut lazy);
    assert_eq!(canonical, lazy);

    let mut group = c.benchmark_group(format!("barrett/slice/u32/mul/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "lazy",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.lazy_reduce_mul_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("barrett/slice/u32/dot_product/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_dot_product(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    group.finish();

    let values: Vec<_> = input.rhs.iter().map(|&value| value.max(1)).collect();
    let elementwise_modulus = UintModulus::new(MODULUS_U32);
    let mut batch_output = vec![0; len];
    let mut elementwise_output = vec![0; len];
    modulus.reduce_inv_slice_to(&values, &mut batch_output);
    elementwise_modulus.reduce_inv_slice_to(&values, &mut elementwise_output);
    assert_eq!(batch_output, elementwise_output);

    let mut group = c.benchmark_group(format!("barrett/slice/u32/inverse_to/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    group.bench_function("batch", |b| {
        b.iter(|| modulus.reduce_inv_slice_to(black_box(&values), black_box(&mut batch_output)))
    });
    group.bench_function("elementwise", |b| {
        b.iter(|| {
            elementwise_modulus
                .reduce_inv_slice_to(black_box(&values), black_box(&mut elementwise_output))
        })
    });
    group.finish();
}

fn bench_barrett_u64(c: &mut Criterion) {
    let input = inputs(MODULUS_U64, POLY_LENGTH);
    let len = input.lhs.len();
    let modulus = BarrettModulus::new(MODULUS_U64);

    let mut canonical = vec![0; len];
    let mut lazy = vec![0; len];
    modulus.reduce_mul_slice_to(&input.lhs, &input.rhs, &mut canonical);
    modulus.lazy_reduce_mul_slice_to(&input.lhs, &input.rhs, &mut lazy);
    modulus.reduce_once_slice_assign(&mut lazy);
    assert_eq!(canonical, lazy);

    let mut group = c.benchmark_group(format!("barrett/slice/u64/mul/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "lazy",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b, out| m.lazy_reduce_mul_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("barrett/slice/u64/dot_product/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_dot_product(
        &mut group,
        "canonical",
        &input.lhs,
        &input.rhs,
        modulus,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    group.finish();

    let values: Vec<_> = input.rhs.iter().map(|&value| value.max(1)).collect();
    let elementwise_modulus = UintModulus::new(MODULUS_U64);
    let mut batch_output = vec![0; len];
    let mut elementwise_output = vec![0; len];
    modulus.reduce_inv_slice_to(&values, &mut batch_output);
    elementwise_modulus.reduce_inv_slice_to(&values, &mut elementwise_output);
    assert_eq!(batch_output, elementwise_output);

    let mut group = c.benchmark_group(format!("barrett/slice/u64/inverse_to/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    group.bench_function("batch", |b| {
        b.iter(|| modulus.reduce_inv_slice_to(black_box(&values), black_box(&mut batch_output)))
    });
    group.bench_function("elementwise", |b| {
        b.iter(|| {
            elementwise_modulus
                .reduce_inv_slice_to(black_box(&values), black_box(&mut elementwise_output))
        })
    });
    group.finish();
}

// Canonical pointwise accumulation used by both GLWE and NTRU PBS.
fn pbs_multiply_add<T: primus_integer::FheUint + Into<u64>>(
    c: &mut Criterion,
    q: T,
    lengths: &[usize],
) {
    for &len in lengths {
        let input = inputs(q, len);
        let modulus = BarrettModulus::new(q);
        let mut acc = vec![T::ZERO; len];
        let mut group = c.benchmark_group(format!("barrett/pbs_mac/u{}/q{q}/n{len}", T::BITS));
        group
            .sample_size(20)
            .warm_up_time(std::time::Duration::from_secs(1))
            .measurement_time(std::time::Duration::from_secs(5));
        group.bench_function("dispatched", |b| {
            b.iter(|| {
                modulus.reduce_add_mul_slice_assign(
                    black_box(&mut acc),
                    black_box(&input.lhs),
                    black_box(&input.rhs),
                )
            })
        });
        group.bench_function("scalar", |b| {
            b.iter(|| {
                for ((acc, &lhs), &rhs) in black_box(&mut acc)
                    .iter_mut()
                    .zip(black_box(&input.lhs))
                    .zip(black_box(&input.rhs))
                {
                    *acc = modulus.reduce_mul_add(lhs, rhs, *acc);
                }
            })
        });
        group.finish();
    }
}

fn bench_barrett_slice(c: &mut Criterion) {
    pbs_multiply_add(c, 132_120_577u32, &[1024, 2048]);
    pbs_multiply_add(c, 1_125_899_906_826_241u64, &[32, 33, 1024, 1025, 2048]);
    // Check the IFMA cutoff and the unchanged full-width Barrett fallback.
    pbs_multiply_add(c, 1u64 << 50, &[1024]);
    pbs_multiply_add(c, (1u64 << 62) - 1, &[1024]);
    bench_barrett_u32(c);
    bench_barrett_u64(c);

    // Scale the distinct u64 kernels without repeating the production length.
    for len in SCALING_LENGTHS {
        if len == POLY_LENGTH {
            continue;
        }

        let input = inputs(MODULUS_U64, len);
        let modulus = BarrettModulus::new(MODULUS_U64);

        let mut group = c.benchmark_group(format!("barrett/slice/u64/mul/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_binary_to(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
        );
        bench_binary_to(
            &mut group,
            "lazy",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b, out| m.lazy_reduce_mul_slice_to(a, b, out),
        );
        group.finish();

        let mut group = c.benchmark_group(format!("barrett/slice/u64/dot_product/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_dot_product(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        group.finish();

        let values: Vec<_> = input.rhs.iter().map(|&value| value.max(1)).collect();
        let elementwise_modulus = UintModulus::new(MODULUS_U64);
        let mut batch_output = vec![0; len];
        let mut elementwise_output = vec![0; len];
        modulus.reduce_inv_slice_to(&values, &mut batch_output);
        elementwise_modulus.reduce_inv_slice_to(&values, &mut elementwise_output);
        assert_eq!(batch_output, elementwise_output);

        let mut group = c.benchmark_group(format!("barrett/slice/u64/inverse_to/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        group.bench_function("batch", |b| {
            b.iter(|| modulus.reduce_inv_slice_to(black_box(&values), black_box(&mut batch_output)))
        });
        group.bench_function("elementwise", |b| {
            b.iter(|| {
                elementwise_modulus
                    .reduce_inv_slice_to(black_box(&values), black_box(&mut elementwise_output))
            })
        });
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = bench_barrett_slice
}
criterion_main!(benches);
