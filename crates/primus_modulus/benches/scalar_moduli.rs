//! Run with `cargo bench -p primus_modulus --bench scalar_moduli`.

mod support;

use criterion::{Criterion, criterion_group, criterion_main, measurement::WallTime};
use primus_modulus::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::prelude::*;
use support::{
    MODULUS_U32, MODULUS_U64, POWER_OF_TWO_U32, POWER_OF_TWO_U64, ScalarInputs, bench_binary,
    bench_ternary, bench_unary, benchmark_config, scalar_inputs_u32, scalar_inputs_u64,
};

macro_rules! benchmark_general_type {
    ($criterion:expr, $type_name:literal, $input:expr, $modulus:expr) => {{
        let input = $input;
        let barrett = BarrettModulus::new($modulus);
        let compact = CompactModulus::new($modulus);
        let uint = UintModulus::new($modulus);

        let first = 0;
        assert_eq!(
            barrett.reduce_add(input.canonical[first], input.rhs[first]),
            compact.reduce_add(input.canonical[first], input.rhs[first])
        );
        assert_eq!(
            barrett.reduce_add(input.canonical[first], input.rhs[first]),
            uint.reduce_add(input.canonical[first], input.rhs[first])
        );

        let mut group = $criterion.benchmark_group(concat!("scalar/general/", $type_name, "/once"));
        bench_unary(
            &mut group,
            "barrett",
            &input.reduce_once,
            barrett,
            |m, x| m.reduce_once(x),
        );
        bench_unary(
            &mut group,
            "compact",
            &input.reduce_once,
            compact,
            |m, x| m.reduce_once(x),
        );
        bench_unary(&mut group, "uint", &input.reduce_once, uint, |m, x| {
            m.reduce_once(x)
        });
        group.finish();

        let mut group = $criterion.benchmark_group(concat!("scalar/general/", $type_name, "/add"));
        bench_binary(
            &mut group,
            "barrett",
            &input.canonical,
            &input.rhs,
            barrett,
            |m, a, b| m.reduce_add(a, b),
        );
        bench_binary(
            &mut group,
            "compact",
            &input.canonical,
            &input.rhs,
            compact,
            |m, a, b| m.reduce_add(a, b),
        );
        bench_binary(
            &mut group,
            "uint",
            &input.canonical,
            &input.rhs,
            uint,
            |m, a, b| m.reduce_add(a, b),
        );
        group.finish();

        let mut group = $criterion.benchmark_group(concat!("scalar/general/", $type_name, "/sub"));
        bench_binary(
            &mut group,
            "barrett",
            &input.canonical,
            &input.rhs,
            barrett,
            |m, a, b| m.reduce_sub(a, b),
        );
        bench_binary(
            &mut group,
            "compact",
            &input.canonical,
            &input.rhs,
            compact,
            |m, a, b| m.reduce_sub(a, b),
        );
        bench_binary(
            &mut group,
            "uint",
            &input.canonical,
            &input.rhs,
            uint,
            |m, a, b| m.reduce_sub(a, b),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/general/", $type_name, "/double"));
        bench_unary(&mut group, "barrett", &input.canonical, barrett, |m, x| {
            m.reduce_double(x)
        });
        bench_unary(&mut group, "compact", &input.canonical, compact, |m, x| {
            m.reduce_double(x)
        });
        bench_unary(&mut group, "uint", &input.canonical, uint, |m, x| {
            m.reduce_double(x)
        });
        group.finish();

        let mut group = $criterion.benchmark_group(concat!("scalar/general/", $type_name, "/neg"));
        bench_unary(&mut group, "barrett", &input.canonical, barrett, |m, x| {
            m.reduce_neg(x)
        });
        bench_unary(&mut group, "compact", &input.canonical, compact, |m, x| {
            m.reduce_neg(x)
        });
        bench_unary(&mut group, "uint", &input.canonical, uint, |m, x| {
            m.reduce_neg(x)
        });
        group.finish();
    }};
}

macro_rules! benchmark_power_of_two_type {
    ($criterion:expr, $type_name:literal, $input:expr, $power_of_two:expr, $value_type:ty) => {{
        let input: ScalarInputs<$value_type> = $input;
        let native = NativeModulus::<$value_type>::new();
        let power_of_two = PowOf2Modulus::<$value_type>::new($power_of_two);

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/once"));
        bench_unary(&mut group, "native", &input.reduce_once, native, |m, x| {
            m.reduce_once(x)
        });
        bench_unary(
            &mut group,
            "pow_of_2",
            &input.reduce_once,
            power_of_two,
            |m, x| m.reduce_once(x),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/add"));
        bench_binary(
            &mut group,
            "native",
            &input.canonical,
            &input.rhs,
            native,
            |m, a, b| m.reduce_add(a, b),
        );
        bench_binary(
            &mut group,
            "pow_of_2",
            &input.canonical,
            &input.rhs,
            power_of_two,
            |m, a, b| m.reduce_add(a, b),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/sub"));
        bench_binary(
            &mut group,
            "native",
            &input.canonical,
            &input.rhs,
            native,
            |m, a, b| m.reduce_sub(a, b),
        );
        bench_binary(
            &mut group,
            "pow_of_2",
            &input.canonical,
            &input.rhs,
            power_of_two,
            |m, a, b| m.reduce_sub(a, b),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/double"));
        bench_unary(&mut group, "native", &input.canonical, native, |m, x| {
            m.reduce_double(x)
        });
        bench_unary(
            &mut group,
            "pow_of_2",
            &input.canonical,
            power_of_two,
            |m, x| m.reduce_double(x),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/neg"));
        bench_unary(&mut group, "native", &input.canonical, native, |m, x| {
            m.reduce_neg(x)
        });
        bench_unary(
            &mut group,
            "pow_of_2",
            &input.canonical,
            power_of_two,
            |m, x| m.reduce_neg(x),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/mul"));
        bench_binary(
            &mut group,
            "native",
            &input.canonical,
            &input.rhs,
            native,
            |m, a, b| m.reduce_mul(a, b),
        );
        bench_binary(
            &mut group,
            "pow_of_2",
            &input.canonical,
            &input.rhs,
            power_of_two,
            |m, a, b| m.reduce_mul(a, b),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/square"));
        bench_unary(&mut group, "native", &input.canonical, native, |m, x| {
            m.reduce_square(x)
        });
        bench_unary(
            &mut group,
            "pow_of_2",
            &input.canonical,
            power_of_two,
            |m, x| m.reduce_square(x),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("scalar/power_of_two/", $type_name, "/mul_add"));
        bench_ternary(
            &mut group,
            "native",
            &input.canonical,
            &input.rhs,
            &input.addend,
            native,
            |m, a, b, c| m.reduce_mul_add(a, b, c),
        );
        bench_ternary(
            &mut group,
            "pow_of_2",
            &input.canonical,
            &input.rhs,
            &input.addend,
            power_of_two,
            |m, a, b, c| m.reduce_mul_add(a, b, c),
        );
        group.finish();
    }};
}

fn bench_scalar_moduli(c: &mut Criterion<WallTime>) {
    benchmark_general_type!(c, "u32", scalar_inputs_u32(MODULUS_U32), MODULUS_U32);
    benchmark_general_type!(c, "u64", scalar_inputs_u64(MODULUS_U64), MODULUS_U64);

    benchmark_power_of_two_type!(
        c,
        "u32",
        scalar_inputs_u32(POWER_OF_TWO_U32),
        POWER_OF_TWO_U32,
        u32
    );
    benchmark_power_of_two_type!(
        c,
        "u64",
        scalar_inputs_u64(POWER_OF_TWO_U64),
        POWER_OF_TWO_U64,
        u64
    );
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = bench_scalar_moduli
}
criterion_main!(benches);
