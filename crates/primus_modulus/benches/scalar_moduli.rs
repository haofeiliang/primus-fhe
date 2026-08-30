//! Run with `cargo bench -p primus_modulus --bench scalar_moduli`.

#[path = "support/scalar.rs"]
mod scalar_support;
mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_modulus::{CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::prelude::*;
use scalar_support::{INPUT_COUNT, MODULUS_U64, bench_binary};
use support::{benchmark_config, inputs};

const POWER_OF_TWO_U64: u64 = 1 << 50;

fn bench_general_u64(c: &mut Criterion) {
    let input = inputs(MODULUS_U64, INPUT_COUNT);
    let compact = CompactModulus::new(MODULUS_U64);
    let uint = UintModulus::new(MODULUS_U64);

    assert_eq!(
        compact.reduce_add(input.lhs[0], input.rhs[0]),
        uint.reduce_add(input.lhs[0], input.rhs[0])
    );

    let mut group = c.benchmark_group("scalar/general/u64/add");
    bench_binary(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b| m.reduce_add(a, b),
    );
    bench_binary(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b| m.reduce_add(a, b),
    );
    group.finish();

    let mut group = c.benchmark_group("scalar/general/u64/sub");
    bench_binary(
        &mut group,
        "compact",
        &input.lhs,
        &input.rhs,
        compact,
        |m, a, b| m.reduce_sub(a, b),
    );
    bench_binary(
        &mut group,
        "uint",
        &input.lhs,
        &input.rhs,
        uint,
        |m, a, b| m.reduce_sub(a, b),
    );
    group.finish();
}

fn bench_power_of_two_u64(c: &mut Criterion) {
    let input = inputs(POWER_OF_TWO_U64, INPUT_COUNT);
    let native = NativeModulus::<u64>::new();
    let power_of_two = PowOf2Modulus::new(POWER_OF_TWO_U64);

    let mut group = c.benchmark_group("scalar/power_of_two/u64/add");
    bench_binary(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b| m.reduce_add(a, b),
    );
    bench_binary(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b| m.reduce_add(a, b),
    );
    group.finish();

    let mut group = c.benchmark_group("scalar/power_of_two/u64/mul");
    bench_binary(
        &mut group,
        "native",
        &input.lhs,
        &input.rhs,
        native,
        |m, a, b| m.reduce_mul(a, b),
    );
    bench_binary(
        &mut group,
        "pow_of_2",
        &input.lhs,
        &input.rhs,
        power_of_two,
        |m, a, b| m.reduce_mul(a, b),
    );
    group.finish();
}

fn bench_scalar_moduli(c: &mut Criterion) {
    bench_general_u64(c);
    bench_power_of_two_u64(c);
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = bench_scalar_moduli
}
criterion_main!(benches);
