//! Run with `cargo bench -p primus_modulus --bench slice_moduli`.
//!
//! To benchmark the SIMD implementation, run
//! `cargo +nightly bench -p primus_modulus --bench slice_moduli --features simd`.

#[path = "support/slice.rs"]
mod slice_support;
mod support;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_modulus::{CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::prelude::*;
use slice_support::{
    MODULUS_U32, MODULUS_U64, POLY_LENGTH, SCALING_LENGTHS, bench_binary_to, bench_dot_product,
};
use support::{benchmark_config, inputs};

const POWER_OF_TWO_U32: u32 = 1 << 29;
const POWER_OF_TWO_U64: u64 = 1 << 50;

fn bench_general_u32(c: &mut Criterion) {
    let input = inputs(MODULUS_U32, POLY_LENGTH);
    let len = input.lhs.len();
    let compact = CompactModulus::new(MODULUS_U32);
    let uint = UintModulus::new(MODULUS_U32);

    let mut compact_output = vec![0; len];
    let mut uint_output = vec![0; len];
    compact.reduce_add_slice_to(&input.lhs, &input.rhs, &mut compact_output);
    uint.reduce_add_slice_to(&input.lhs, &input.rhs, &mut uint_output);
    assert_eq!(compact_output, uint_output);

    let mut group = c.benchmark_group(format!("slice/general/u32/add/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("slice/general/u32/sub/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b, out| m.reduce_sub_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b, out| m.reduce_sub_slice_to(a, b, out),
    );
    group.finish();
}

fn bench_general_u64(c: &mut Criterion) {
    let input = inputs(MODULUS_U64, POLY_LENGTH);
    let len = input.lhs.len();
    let compact = CompactModulus::new(MODULUS_U64);
    let uint = UintModulus::new(MODULUS_U64);

    let mut compact_output = vec![0; len];
    let mut uint_output = vec![0; len];
    compact.reduce_add_slice_to(&input.lhs, &input.rhs, &mut compact_output);
    uint.reduce_add_slice_to(&input.lhs, &input.rhs, &mut uint_output);
    assert_eq!(compact_output, uint_output);

    let mut group = c.benchmark_group(format!("slice/general/u64/add/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("slice/general/u64/sub/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b, out| m.reduce_sub_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b, out| m.reduce_sub_slice_to(a, b, out),
    );
    group.finish();
}

fn bench_power_of_two_u32(c: &mut Criterion) {
    let input = inputs(POWER_OF_TWO_U32, POLY_LENGTH);
    let len = input.lhs.len();
    let native = NativeModulus::<u32>::new();
    let power_of_two = PowOf2Modulus::new(POWER_OF_TWO_U32);

    let mut group = c.benchmark_group(format!("slice/power_of_two/u32/add/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("slice/power_of_two/u32/mul/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("slice/power_of_two/u32/dot_product/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_dot_product(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    bench_dot_product(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    group.finish();
}

fn bench_power_of_two_u64(c: &mut Criterion) {
    let input = inputs(POWER_OF_TWO_U64, POLY_LENGTH);
    let len = input.lhs.len();
    let native = NativeModulus::<u64>::new();
    let power_of_two = PowOf2Modulus::new(POWER_OF_TWO_U64);

    let mut group = c.benchmark_group(format!("slice/power_of_two/u64/add/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b, out| m.reduce_add_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("slice/power_of_two/u64/mul/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_binary_to(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    bench_binary_to(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
    );
    group.finish();

    let mut group = c.benchmark_group(format!("slice/power_of_two/u64/dot_product/{len}"));
    group.throughput(Throughput::Elements(len as u64));
    bench_dot_product(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    bench_dot_product(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b| m.reduce_dot_product(a, b),
    );
    group.finish();
}

fn bench_slice_moduli(c: &mut Criterion) {
    bench_general_u32(c);
    bench_general_u64(c);
    bench_power_of_two_u32(c);
    bench_power_of_two_u64(c);

    // Only representative u64 kernels receive a full length sweep. The same
    // operations at the production polynomial length are registered above.
    for len in SCALING_LENGTHS {
        if len == POLY_LENGTH {
            continue;
        }

        let input = inputs(MODULUS_U64, len);
        let compact = CompactModulus::new(MODULUS_U64);
        let uint = UintModulus::new(MODULUS_U64);
        let mut group = c.benchmark_group(format!("slice/general/u64/add/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_binary_to(
            &mut group,
            "compact",
            &input.lhs,
            &input.rhs,
            compact,
            |m, a, b, out| m.reduce_add_slice_to(a, b, out),
        );
        bench_binary_to(
            &mut group,
            "uint",
            &input.lhs,
            &input.rhs,
            uint,
            |m, a, b, out| m.reduce_add_slice_to(a, b, out),
        );
        group.finish();

        let input = inputs(POWER_OF_TWO_U64, len);
        let native = NativeModulus::<u64>::new();
        let power_of_two = PowOf2Modulus::new(POWER_OF_TWO_U64);
        let mut group = c.benchmark_group(format!("slice/power_of_two/u64/mul/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_binary_to(
            &mut group,
            "native",
            &input.lhs,
            &input.rhs,
            native,
            |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
        );
        bench_binary_to(
            &mut group,
            "pow_of_2",
            &input.lhs,
            &input.rhs,
            power_of_two,
            |m, a, b, out| m.reduce_mul_slice_to(a, b, out),
        );
        group.finish();

        let mut group = c.benchmark_group(format!("slice/power_of_two/u64/dot_product/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_dot_product(
            &mut group,
            "native",
            &input.lhs,
            &input.rhs,
            native,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        bench_dot_product(
            &mut group,
            "pow_of_2",
            &input.lhs,
            &input.rhs,
            power_of_two,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = bench_slice_moduli
}
criterion_main!(benches);
