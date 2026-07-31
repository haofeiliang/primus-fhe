//! Run with `cargo bench -p primus_modulus --bench barrett_scalar`.

mod support;

use criterion::{Criterion, criterion_group, criterion_main};
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;
use support::{
    MODULUS_U32, MODULUS_U64, bench_binary, bench_ternary, bench_unary, benchmark_config,
    scalar_inputs_u32, scalar_inputs_u64,
};

macro_rules! benchmark_barrett_arithmetic {
    ($criterion:expr, $type_name:literal, $input:expr, $modulus_value:expr) => {{
        let input = $input;
        let modulus = BarrettModulus::new($modulus_value);

        assert_eq!(
            modulus.reduce_once(modulus.lazy_reduce(input.full_width[0])),
            modulus.reduce(input.full_width[0])
        );
        assert_eq!(
            modulus.reduce_once(modulus.lazy_reduce_mul(input.canonical[0], input.rhs[0])),
            modulus.reduce_mul(input.canonical[0], input.rhs[0])
        );

        let mut group =
            $criterion.benchmark_group(concat!("barrett/scalar/", $type_name, "/reduce_word"));
        bench_unary(
            &mut group,
            "canonical",
            &input.full_width,
            modulus,
            |m, x| m.reduce(x),
        );
        bench_unary(&mut group, "lazy", &input.full_width, modulus, |m, x| {
            m.lazy_reduce(x)
        });
        group.finish();

        let mut group = $criterion.benchmark_group(concat!("barrett/scalar/", $type_name, "/mul"));
        bench_binary(
            &mut group,
            "canonical",
            &input.canonical,
            &input.rhs,
            modulus,
            |m, a, b| m.reduce_mul(a, b),
        );
        bench_binary(
            &mut group,
            "lazy",
            &input.canonical,
            &input.rhs,
            modulus,
            |m, a, b| m.lazy_reduce_mul(a, b),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("barrett/scalar/", $type_name, "/square"));
        bench_unary(
            &mut group,
            "canonical",
            &input.canonical,
            modulus,
            |m, x| m.reduce_square(x),
        );
        group.finish();

        let mut group =
            $criterion.benchmark_group(concat!("barrett/scalar/", $type_name, "/mul_add"));
        bench_ternary(
            &mut group,
            "canonical",
            &input.canonical,
            &input.rhs,
            &input.addend,
            modulus,
            |m, a, b, c| m.reduce_mul_add(a, b, c),
        );
        bench_ternary(
            &mut group,
            "lazy",
            &input.canonical,
            &input.rhs,
            &input.addend,
            modulus,
            |m, a, b, c| m.lazy_reduce_mul_add(a, b, c),
        );
        group.finish();
    }};
}

fn bench_wide_reduction(c: &mut Criterion) {
    let input_u32 = scalar_inputs_u32(MODULUS_U32);
    let wide_u32: Vec<[u32; 2]> = input_u32
        .full_width
        .iter()
        .copied()
        .zip(input_u32.full_width.iter().copied().cycle().skip(1))
        .map(|(lo, hi)| [lo, hi])
        .collect();
    let modulus_u32 = BarrettModulus::new(MODULUS_U32);

    let mut group = c.benchmark_group("barrett/scalar/u32/reduce_wide");
    bench_unary(&mut group, "canonical", &wide_u32, modulus_u32, |m, x| {
        m.reduce(x)
    });
    bench_unary(&mut group, "lazy", &wide_u32, modulus_u32, |m, x| {
        m.lazy_reduce(x)
    });
    group.finish();

    let input_u64 = scalar_inputs_u64(MODULUS_U64);
    let wide_u64: Vec<[u64; 2]> = input_u64
        .full_width
        .iter()
        .copied()
        .zip(input_u64.full_width.iter().copied().cycle().skip(1))
        .map(|(lo, hi)| [lo, hi])
        .collect();
    let (multi_limb_u64, remainder) = input_u64.full_width.as_chunks::<4>();
    assert!(remainder.is_empty());
    let multi_limb_u64 = multi_limb_u64.to_vec();
    let modulus_u64 = BarrettModulus::new(MODULUS_U64);

    let mut group = c.benchmark_group("barrett/scalar/u64/reduce_wide");
    bench_unary(&mut group, "canonical", &wide_u64, modulus_u64, |m, x| {
        m.reduce(x)
    });
    bench_unary(&mut group, "lazy", &wide_u64, modulus_u64, |m, x| {
        m.lazy_reduce(x)
    });
    group.finish();

    let mut group = c.benchmark_group("barrett/scalar/u64/reduce_multi_limb");
    bench_unary(
        &mut group,
        "4_limbs_canonical",
        &multi_limb_u64,
        modulus_u64,
        |m, x| m.reduce(x.as_slice()),
    );
    bench_unary(
        &mut group,
        "4_limbs_lazy",
        &multi_limb_u64,
        modulus_u64,
        |m, x| m.lazy_reduce(x.as_slice()),
    );
    group.finish();
}

fn bench_inverse_division_and_exponentiation(c: &mut Criterion) {
    let input = scalar_inputs_u64(MODULUS_U64);
    let modulus = BarrettModulus::new(MODULUS_U64);

    let mut group = c.benchmark_group("barrett/scalar/u64/inverse_division");
    bench_unary(&mut group, "inverse", &input.nonzero, modulus, |m, x| {
        m.reduce_inv(x)
    });
    bench_binary(
        &mut group,
        "division",
        &input.canonical,
        &input.nonzero,
        modulus,
        |m, a, b| m.reduce_div(a, b),
    );
    group.finish();

    const EXPONENT_LOG: u32 = 16;
    const EXPONENT: u64 = 1 << EXPONENT_LOG;

    let mut group = c.benchmark_group("barrett/scalar/u64/exp_power_of_two");
    bench_unary(&mut group, "generic", &input.canonical, modulus, |m, x| {
        m.reduce_exp(x, EXPONENT)
    });
    bench_unary(
        &mut group,
        "specialized",
        &input.canonical,
        modulus,
        |m, x| m.reduce_exp_power_of_2(x, EXPONENT_LOG),
    );
    group.finish();
}

fn bench_barrett_scalar(c: &mut Criterion) {
    benchmark_barrett_arithmetic!(c, "u32", scalar_inputs_u32(MODULUS_U32), MODULUS_U32);
    benchmark_barrett_arithmetic!(c, "u64", scalar_inputs_u64(MODULUS_U64), MODULUS_U64);
    bench_wide_reduction(c);
    bench_inverse_division_and_exponentiation(c);
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = bench_barrett_scalar
}
criterion_main!(benches);
