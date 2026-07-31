//! Run with `cargo bench -p primus_modulus --bench slice_moduli`.
//!
//! To benchmark the SIMD implementation, run
//! `cargo +nightly bench -p primus_modulus --bench slice_moduli --features simd`.

mod support;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use primus_modulus::{BarrettModulus, CompactModulus, NativeModulus, PowOf2Modulus, UintModulus};
use primus_reduce::prelude::*;
use support::{
    MODULUS_U32, MODULUS_U64, POLY_LENGTH, POWER_OF_TWO_U32, POWER_OF_TWO_U64, SCALING_LENGTHS,
    SliceInputs, bench_slice_binary_to, bench_slice_dot_product, bench_slice_scalar_to,
    bench_slice_ternary_to, bench_slice_unary_to, benchmark_config, slice_inputs_u32,
    slice_inputs_u64,
};

macro_rules! general_slice_group_unary {
    ($criterion:expr, $type_name:literal, $operation:literal, $input:expr, $barrett:expr, $compact:expr, $uint:expr, $method:ident) => {{
        let len = $input.len();
        let mut group = $criterion.benchmark_group(format!(
            "slice/general/{}/{}/{}",
            $type_name, $operation, len
        ));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_unary_to(&mut group, "barrett", $input, $barrett, |m, x, out| {
            m.$method(x, out)
        });
        bench_slice_unary_to(&mut group, "compact", $input, $compact, |m, x, out| {
            m.$method(x, out)
        });
        bench_slice_unary_to(&mut group, "uint", $input, $uint, |m, x, out| {
            m.$method(x, out)
        });
        group.finish();
    }};
}

macro_rules! general_slice_group_binary {
    ($criterion:expr, $type_name:literal, $operation:literal, $lhs:expr, $rhs:expr, $barrett:expr, $compact:expr, $uint:expr, $method:ident) => {{
        let len = $lhs.len();
        let mut group = $criterion.benchmark_group(format!(
            "slice/general/{}/{}/{}",
            $type_name, $operation, len
        ));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_binary_to(
            &mut group,
            "barrett",
            $lhs,
            $rhs,
            $barrett,
            |m, a, b, out| m.$method(a, b, out),
        );
        bench_slice_binary_to(
            &mut group,
            "compact",
            $lhs,
            $rhs,
            $compact,
            |m, a, b, out| m.$method(a, b, out),
        );
        bench_slice_binary_to(&mut group, "uint", $lhs, $rhs, $uint, |m, a, b, out| {
            m.$method(a, b, out)
        });
        group.finish();
    }};
}

macro_rules! benchmark_general_slices {
    ($criterion:expr, $type_name:literal, $input:expr, $modulus_value:expr) => {{
        let input = $input;
        let barrett = BarrettModulus::new($modulus_value);
        let compact = CompactModulus::new($modulus_value);
        let uint = UintModulus::new($modulus_value);

        let mut barrett_output = vec![0; input.lhs.len()];
        let mut compact_output = vec![0; input.lhs.len()];
        let mut uint_output = vec![0; input.lhs.len()];
        barrett.reduce_add_slice_to(&input.lhs, &input.rhs, &mut barrett_output);
        compact.reduce_add_slice_to(&input.lhs, &input.rhs, &mut compact_output);
        uint.reduce_add_slice_to(&input.lhs, &input.rhs, &mut uint_output);
        assert_eq!(barrett_output, compact_output);
        assert_eq!(barrett_output, uint_output);

        general_slice_group_unary!(
            $criterion,
            $type_name,
            "once",
            &input.reduce_once,
            barrett,
            compact,
            uint,
            reduce_once_slice_to
        );
        general_slice_group_binary!(
            $criterion,
            $type_name,
            "add",
            &input.lhs,
            &input.rhs,
            barrett,
            compact,
            uint,
            reduce_add_slice_to
        );
        general_slice_group_binary!(
            $criterion,
            $type_name,
            "sub",
            &input.lhs,
            &input.rhs,
            barrett,
            compact,
            uint,
            reduce_sub_slice_to
        );
        general_slice_group_unary!(
            $criterion,
            $type_name,
            "double",
            &input.lhs,
            barrett,
            compact,
            uint,
            reduce_double_slice_to
        );
        general_slice_group_unary!(
            $criterion,
            $type_name,
            "neg",
            &input.lhs,
            barrett,
            compact,
            uint,
            reduce_neg_slice_to
        );
        general_slice_group_unary!(
            $criterion,
            $type_name,
            "inverse",
            &input.nonzero,
            barrett,
            compact,
            uint,
            reduce_inv_slice_to
        );
    }};
}

macro_rules! power_of_two_slice_group_unary {
    ($criterion:expr, $type_name:literal, $operation:literal, $input:expr, $native:expr, $power_of_two:expr, $method:ident) => {{
        let len = $input.len();
        let mut group = $criterion.benchmark_group(format!(
            "slice/power_of_two/{}/{}/{}",
            $type_name, $operation, len
        ));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_unary_to(&mut group, "native", $input, $native, |m, x, out| {
            m.$method(x, out)
        });
        bench_slice_unary_to(
            &mut group,
            "pow_of_2",
            $input,
            $power_of_two,
            |m, x, out| m.$method(x, out),
        );
        group.finish();
    }};
}

macro_rules! power_of_two_slice_group_binary {
    ($criterion:expr, $type_name:literal, $operation:literal, $lhs:expr, $rhs:expr, $native:expr, $power_of_two:expr, $method:ident) => {{
        let len = $lhs.len();
        let mut group = $criterion.benchmark_group(format!(
            "slice/power_of_two/{}/{}/{}",
            $type_name, $operation, len
        ));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_binary_to(&mut group, "native", $lhs, $rhs, $native, |m, a, b, out| {
            m.$method(a, b, out)
        });
        bench_slice_binary_to(
            &mut group,
            "pow_of_2",
            $lhs,
            $rhs,
            $power_of_two,
            |m, a, b, out| m.$method(a, b, out),
        );
        group.finish();
    }};
}

macro_rules! benchmark_power_of_two_slices {
    ($criterion:expr, $type_name:literal, $input:expr, $power_of_two_value:expr, $value_type:ty) => {{
        let input: SliceInputs<$value_type> = $input;
        let native = NativeModulus::<$value_type>::new();
        let power_of_two = PowOf2Modulus::<$value_type>::new($power_of_two_value);

        power_of_two_slice_group_unary!(
            $criterion,
            $type_name,
            "once",
            &input.reduce_once,
            native,
            power_of_two,
            reduce_once_slice_to
        );
        power_of_two_slice_group_binary!(
            $criterion,
            $type_name,
            "add",
            &input.lhs,
            &input.rhs,
            native,
            power_of_two,
            reduce_add_slice_to
        );
        power_of_two_slice_group_binary!(
            $criterion,
            $type_name,
            "sub",
            &input.lhs,
            &input.rhs,
            native,
            power_of_two,
            reduce_sub_slice_to
        );
        power_of_two_slice_group_unary!(
            $criterion,
            $type_name,
            "double",
            &input.lhs,
            native,
            power_of_two,
            reduce_double_slice_to
        );
        power_of_two_slice_group_unary!(
            $criterion,
            $type_name,
            "neg",
            &input.lhs,
            native,
            power_of_two,
            reduce_neg_slice_to
        );
        power_of_two_slice_group_binary!(
            $criterion,
            $type_name,
            "mul",
            &input.lhs,
            &input.rhs,
            native,
            power_of_two,
            reduce_mul_slice_to
        );

        let len = input.lhs.len();
        let scalar = input.rhs[0];
        let mut group = $criterion.benchmark_group(format!(
            "slice/power_of_two/{}/mul_scalar/{}",
            $type_name, len
        ));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_scalar_to(
            &mut group,
            "native",
            &input.lhs,
            scalar,
            native,
            |m, x, scalar, out| m.reduce_mul_scalar_slice_to(x, scalar, out),
        );
        bench_slice_scalar_to(
            &mut group,
            "pow_of_2",
            &input.lhs,
            scalar,
            power_of_two,
            |m, x, scalar, out| m.reduce_mul_scalar_slice_to(x, scalar, out),
        );
        group.finish();

        let mut group = $criterion
            .benchmark_group(format!("slice/power_of_two/{}/mul_add/{}", $type_name, len));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_ternary_to(
            &mut group,
            "native",
            &input.lhs,
            &input.rhs,
            &input.addend,
            native,
            |m, a, b, c, out| m.reduce_mul_add_slice_to(a, b, c, out),
        );
        bench_slice_ternary_to(
            &mut group,
            "pow_of_2",
            &input.lhs,
            &input.rhs,
            &input.addend,
            power_of_two,
            |m, a, b, c, out| m.reduce_mul_add_slice_to(a, b, c, out),
        );
        group.finish();

        let mut group = $criterion.benchmark_group(format!(
            "slice/power_of_two/{}/dot_product/{}",
            $type_name, len
        ));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_dot_product(
            &mut group,
            "native",
            &input.lhs,
            &input.rhs,
            native,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        bench_slice_dot_product(
            &mut group,
            "pow_of_2",
            &input.lhs,
            &input.rhs,
            power_of_two,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        group.finish();
    }};
}

fn bench_slice_moduli(c: &mut Criterion) {
    benchmark_general_slices!(
        c,
        "u32",
        slice_inputs_u32(MODULUS_U32, POLY_LENGTH),
        MODULUS_U32
    );
    benchmark_general_slices!(
        c,
        "u64",
        slice_inputs_u64(MODULUS_U64, POLY_LENGTH),
        MODULUS_U64
    );
    benchmark_power_of_two_slices!(
        c,
        "u32",
        slice_inputs_u32(POWER_OF_TWO_U32, POLY_LENGTH),
        POWER_OF_TWO_U32,
        u32
    );
    benchmark_power_of_two_slices!(
        c,
        "u64",
        slice_inputs_u64(POWER_OF_TWO_U64, POLY_LENGTH),
        POWER_OF_TWO_U64,
        u64
    );

    // Only representative u64 kernels receive a full length sweep. The full
    // operation matrix above stays at the production polynomial length.
    for len in SCALING_LENGTHS {
        if len == POLY_LENGTH {
            continue;
        }

        let input = slice_inputs_u64(MODULUS_U64, len);
        let barrett = BarrettModulus::new(MODULUS_U64);
        let compact = CompactModulus::new(MODULUS_U64);
        let uint = UintModulus::new(MODULUS_U64);
        general_slice_group_binary!(
            c,
            "u64",
            "add",
            &input.lhs,
            &input.rhs,
            barrett,
            compact,
            uint,
            reduce_add_slice_to
        );

        let input = slice_inputs_u64(POWER_OF_TWO_U64, len);
        let native = NativeModulus::<u64>::new();
        let power_of_two = PowOf2Modulus::new(POWER_OF_TWO_U64);
        power_of_two_slice_group_binary!(
            c,
            "u64",
            "mul",
            &input.lhs,
            &input.rhs,
            native,
            power_of_two,
            reduce_mul_slice_to
        );

        let mut group = c.benchmark_group(format!("slice/power_of_two/u64/dot_product/{len}"));
        group.throughput(Throughput::Elements(len as u64));
        bench_slice_dot_product(
            &mut group,
            "native",
            &input.lhs,
            &input.rhs,
            native,
            |m, a, b| m.reduce_dot_product(a, b),
        );
        bench_slice_dot_product(
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
