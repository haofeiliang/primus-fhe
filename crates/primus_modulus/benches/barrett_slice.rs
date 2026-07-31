//! Run with `cargo bench -p primus_modulus --bench barrett_slice`.
//!
//! To benchmark the SIMD implementation, run
//! `cargo +nightly bench -p primus_modulus --bench barrett_slice --features simd`.

mod support;

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;
use support::{
    MODULUS_U32, MODULUS_U64, POLY_LENGTH, SCALING_LENGTHS, bench_slice_binary_to,
    bench_slice_dot_product, bench_slice_scalar_to, bench_slice_ternary_to, benchmark_config,
    slice_inputs_u32, slice_inputs_u64,
};

macro_rules! benchmark_barrett_slices {
    ($criterion:expr, $type_name:literal, $input:expr, $modulus_value:expr) => {{
        let input = $input;
        let len = input.lhs.len();
        let modulus = BarrettModulus::new($modulus_value);

        let mut canonical = vec![0; len];
        let mut lazy = vec![0; len];
        modulus.reduce_mul_slice_to(&input.lhs, &input.rhs, &mut canonical);
        modulus.lazy_reduce_mul_slice_to(&input.lhs, &input.rhs, &mut lazy);
        modulus.reduce_once_slice_assign(&mut lazy);
        assert_eq!(canonical, lazy);

        let mut group =
            $criterion.benchmark_group(format!("barrett/slice/{}/mul/{}", $type_name, len));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_binary_to(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
        );
        bench_slice_binary_to(
            &mut group,
            "lazy",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b, out| m.lazy_reduce_mul_slice_to(a, b, out),
        );
        group.finish();

        let scalar = input.rhs[0];
        let mut group =
            $criterion.benchmark_group(format!("barrett/slice/{}/mul_scalar/{}", $type_name, len));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_scalar_to(
            &mut group,
            "canonical",
            &input.lhs,
            scalar,
            modulus,
            |m, a, scalar, out| m.reduce_mul_scalar_slice_to(a, scalar, out),
        );
        bench_slice_scalar_to(
            &mut group,
            "lazy",
            &input.lhs,
            scalar,
            modulus,
            |m, a, scalar, out| m.lazy_reduce_mul_scalar_slice_to(a, scalar, out),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(format!("barrett/slice/{}/mul_add/{}", $type_name, len));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_ternary_to(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            &input.addend,
            modulus,
            |m, a, b, c, out| m.reduce_mul_add_slice_to(a, b, c, out),
        );
        bench_slice_ternary_to(
            &mut group,
            "lazy",
            &input.lhs,
            &input.rhs,
            &input.addend,
            modulus,
            |m, a, b, c, out| m.lazy_reduce_mul_add_slice_to(a, b, c, out),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(format!("barrett/slice/{}/dot_product/{}", $type_name, len));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_dot_product(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        group.finish();

        let mut values = input.nonzero.clone();
        let mut scratch = vec![0; len];
        let mut group = $criterion.benchmark_group(format!(
            "barrett/slice/{}/inverse_assign/{}",
            $type_name, len
        ));
        group.throughput(Throughput::Elements(len as u64));
        group.bench_function("batch", |b| {
            b.iter(|| {
                modulus.reduce_inv_slice_assign(black_box(&mut values), black_box(&mut scratch))
            })
        });
        group.finish();
    }};
}

fn bench_barrett_slice(c: &mut Criterion) {
    benchmark_barrett_slices!(
        c,
        "u32",
        slice_inputs_u32(MODULUS_U32, POLY_LENGTH),
        MODULUS_U32
    );
    benchmark_barrett_slices!(
        c,
        "u64",
        slice_inputs_u64(MODULUS_U64, POLY_LENGTH),
        MODULUS_U64
    );

    // Scale only the most important u64 kernels; the full matrix remains at
    // the production polynomial length above.
    for len in SCALING_LENGTHS {
        if len == POLY_LENGTH {
            continue;
        }

        let input = slice_inputs_u64(MODULUS_U64, len);
        let modulus = BarrettModulus::new(MODULUS_U64);

        let mut group = c.benchmark_group(format!("barrett/slice/u64/mul/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_binary_to(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
        );
        bench_slice_binary_to(
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
        bench_slice_dot_product(
            &mut group,
            "canonical",
            &input.lhs,
            &input.rhs,
            modulus,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        group.finish();

        let mut values = input.nonzero;
        let mut scratch = vec![0; len];
        let mut group = c.benchmark_group(format!("barrett/slice/u64/inverse_assign/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        group.bench_function("batch", |b| {
            b.iter(|| {
                modulus.reduce_inv_slice_assign(black_box(&mut values), black_box(&mut scratch))
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
