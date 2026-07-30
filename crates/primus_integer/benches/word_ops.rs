#![cfg_attr(feature = "simd", feature(portable_simd))]

mod support;

use std::hint::black_box;
#[cfg(feature = "simd")]
use std::simd::Simd;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::{CarryingMul, WideningMul};
use rand::distr::{Distribution, Uniform};
use rand::{SeedableRng, rngs::StdRng};

use support::{RNG_SEED, sampled_values};

const BATCH_LEN: usize = 8192;

struct WordInputs<T> {
    lhs: Vec<T>,
    rhs: Vec<T>,
    carry: Vec<T>,
    add: Vec<T>,
}

fn word_inputs<T, D>(rng: &mut StdRng, distribution: &D) -> WordInputs<T>
where
    D: Distribution<T>,
{
    WordInputs {
        lhs: sampled_values(rng, distribution, BATCH_LEN),
        rhs: sampled_values(rng, distribution, BATCH_LEN),
        carry: sampled_values(rng, distribution, BATCH_LEN),
        add: sampled_values(rng, distribution, BATCH_LEN),
    }
}

macro_rules! bench_scalar_word_ops {
    ($group:expr, $type_name:literal, $ty:ty, $inputs:expr) => {{
        let inputs = &$inputs;
        let mut low = vec![0 as $ty; BATCH_LEN];
        let mut high = vec![0 as $ty; BATCH_LEN];

        $group.bench_function(BenchmarkId::new("widening_mul", $type_name), |b| {
            b.iter(|| {
                let lhs = black_box(inputs.lhs.as_slice());
                let rhs = black_box(inputs.rhs.as_slice());
                let low = black_box(low.as_mut_slice());
                let high = black_box(high.as_mut_slice());

                for index in 0..BATCH_LEN {
                    (low[index], high[index]) = WideningMul::widening_mul(lhs[index], rhs[index]);
                }
            })
        });

        $group.bench_function(BenchmarkId::new("widening_mul_hw", $type_name), |b| {
            b.iter(|| {
                let lhs = black_box(inputs.lhs.as_slice());
                let rhs = black_box(inputs.rhs.as_slice());
                let high = black_box(high.as_mut_slice());

                for index in 0..BATCH_LEN {
                    high[index] = WideningMul::widening_mul_hw(lhs[index], rhs[index]);
                }
            })
        });

        $group.bench_function(BenchmarkId::new("carrying_mul", $type_name), |b| {
            b.iter(|| {
                let lhs = black_box(inputs.lhs.as_slice());
                let rhs = black_box(inputs.rhs.as_slice());
                let carry = black_box(inputs.carry.as_slice());
                let low = black_box(low.as_mut_slice());
                let high = black_box(high.as_mut_slice());

                for index in 0..BATCH_LEN {
                    (low[index], high[index]) =
                        CarryingMul::carrying_mul(lhs[index], rhs[index], carry[index]);
                }
            })
        });

        $group.bench_function(BenchmarkId::new("carrying_mul_hw", $type_name), |b| {
            b.iter(|| {
                let lhs = black_box(inputs.lhs.as_slice());
                let rhs = black_box(inputs.rhs.as_slice());
                let carry = black_box(inputs.carry.as_slice());
                let high = black_box(high.as_mut_slice());

                for index in 0..BATCH_LEN {
                    high[index] =
                        CarryingMul::carrying_mul_hw(lhs[index], rhs[index], carry[index]);
                }
            })
        });

        $group.bench_function(BenchmarkId::new("carrying_mul_add", $type_name), |b| {
            b.iter(|| {
                let lhs = black_box(inputs.lhs.as_slice());
                let rhs = black_box(inputs.rhs.as_slice());
                let carry = black_box(inputs.carry.as_slice());
                let add = black_box(inputs.add.as_slice());
                let low = black_box(low.as_mut_slice());
                let high = black_box(high.as_mut_slice());

                for index in 0..BATCH_LEN {
                    (low[index], high[index]) = CarryingMul::carrying_mul_add(
                        lhs[index],
                        rhs[index],
                        carry[index],
                        add[index],
                    );
                }
            })
        });
    }};
}

#[cfg(feature = "simd")]
macro_rules! bench_simd_word_ops {
    ($group:expr, $type_name:literal, $ty:ty, $lanes:literal, $inputs:expr) => {{
        let inputs = &$inputs;
        let mut low = vec![0 as $ty; BATCH_LEN];
        let mut high = vec![0 as $ty; BATCH_LEN];

        $group.bench_function(BenchmarkId::new("simd_widening_mul", $type_name), |b| {
            b.iter(|| {
                let (lhs, lhs_tail) = black_box(inputs.lhs.as_slice()).as_chunks::<$lanes>();
                let (rhs, rhs_tail) = black_box(inputs.rhs.as_slice()).as_chunks::<$lanes>();
                let (low, low_tail) = black_box(low.as_mut_slice()).as_chunks_mut::<$lanes>();
                let (high, high_tail) = black_box(high.as_mut_slice()).as_chunks_mut::<$lanes>();
                debug_assert!(
                    lhs_tail.is_empty()
                        && rhs_tail.is_empty()
                        && low_tail.is_empty()
                        && high_tail.is_empty()
                );

                for index in 0..lhs.len() {
                    let lhs = Simd::<$ty, $lanes>::from_array(lhs[index]);
                    let rhs = Simd::<$ty, $lanes>::from_array(rhs[index]);
                    let (result_low, result_high) = WideningMul::widening_mul(lhs, rhs);
                    low[index] = result_low.to_array();
                    high[index] = result_high.to_array();
                }
            })
        });

        $group.bench_function(BenchmarkId::new("simd_widening_mul_hw", $type_name), |b| {
            b.iter(|| {
                let (lhs, lhs_tail) = black_box(inputs.lhs.as_slice()).as_chunks::<$lanes>();
                let (rhs, rhs_tail) = black_box(inputs.rhs.as_slice()).as_chunks::<$lanes>();
                let (high, high_tail) = black_box(high.as_mut_slice()).as_chunks_mut::<$lanes>();
                debug_assert!(lhs_tail.is_empty() && rhs_tail.is_empty() && high_tail.is_empty());

                for index in 0..lhs.len() {
                    let lhs = Simd::<$ty, $lanes>::from_array(lhs[index]);
                    let rhs = Simd::<$ty, $lanes>::from_array(rhs[index]);
                    high[index] = WideningMul::widening_mul_hw(lhs, rhs).to_array();
                }
            })
        });

        $group.bench_function(BenchmarkId::new("simd_carrying_mul", $type_name), |b| {
            b.iter(|| {
                let (lhs, lhs_tail) = black_box(inputs.lhs.as_slice()).as_chunks::<$lanes>();
                let (rhs, rhs_tail) = black_box(inputs.rhs.as_slice()).as_chunks::<$lanes>();
                let (carry, carry_tail) = black_box(inputs.carry.as_slice()).as_chunks::<$lanes>();
                let (low, low_tail) = black_box(low.as_mut_slice()).as_chunks_mut::<$lanes>();
                let (high, high_tail) = black_box(high.as_mut_slice()).as_chunks_mut::<$lanes>();
                debug_assert!(
                    lhs_tail.is_empty()
                        && rhs_tail.is_empty()
                        && carry_tail.is_empty()
                        && low_tail.is_empty()
                        && high_tail.is_empty()
                );

                for index in 0..lhs.len() {
                    let lhs = Simd::<$ty, $lanes>::from_array(lhs[index]);
                    let rhs = Simd::<$ty, $lanes>::from_array(rhs[index]);
                    let carry = Simd::<$ty, $lanes>::from_array(carry[index]);
                    let (result_low, result_high) = CarryingMul::carrying_mul(lhs, rhs, carry);
                    low[index] = result_low.to_array();
                    high[index] = result_high.to_array();
                }
            })
        });

        $group.bench_function(BenchmarkId::new("simd_carrying_mul_hw", $type_name), |b| {
            b.iter(|| {
                let (lhs, lhs_tail) = black_box(inputs.lhs.as_slice()).as_chunks::<$lanes>();
                let (rhs, rhs_tail) = black_box(inputs.rhs.as_slice()).as_chunks::<$lanes>();
                let (carry, carry_tail) = black_box(inputs.carry.as_slice()).as_chunks::<$lanes>();
                let (high, high_tail) = black_box(high.as_mut_slice()).as_chunks_mut::<$lanes>();
                debug_assert!(
                    lhs_tail.is_empty()
                        && rhs_tail.is_empty()
                        && carry_tail.is_empty()
                        && high_tail.is_empty()
                );

                for index in 0..lhs.len() {
                    let lhs = Simd::<$ty, $lanes>::from_array(lhs[index]);
                    let rhs = Simd::<$ty, $lanes>::from_array(rhs[index]);
                    let carry = Simd::<$ty, $lanes>::from_array(carry[index]);
                    high[index] = CarryingMul::carrying_mul_hw(lhs, rhs, carry).to_array();
                }
            })
        });

        $group.bench_function(BenchmarkId::new("simd_carrying_mul_add", $type_name), |b| {
            b.iter(|| {
                let (lhs, lhs_tail) = black_box(inputs.lhs.as_slice()).as_chunks::<$lanes>();
                let (rhs, rhs_tail) = black_box(inputs.rhs.as_slice()).as_chunks::<$lanes>();
                let (carry, carry_tail) = black_box(inputs.carry.as_slice()).as_chunks::<$lanes>();
                let (add, add_tail) = black_box(inputs.add.as_slice()).as_chunks::<$lanes>();
                let (low, low_tail) = black_box(low.as_mut_slice()).as_chunks_mut::<$lanes>();
                let (high, high_tail) = black_box(high.as_mut_slice()).as_chunks_mut::<$lanes>();
                debug_assert!(
                    lhs_tail.is_empty()
                        && rhs_tail.is_empty()
                        && carry_tail.is_empty()
                        && add_tail.is_empty()
                        && low_tail.is_empty()
                        && high_tail.is_empty()
                );

                for index in 0..lhs.len() {
                    let lhs = Simd::<$ty, $lanes>::from_array(lhs[index]);
                    let rhs = Simd::<$ty, $lanes>::from_array(rhs[index]);
                    let carry = Simd::<$ty, $lanes>::from_array(carry[index]);
                    let add = Simd::<$ty, $lanes>::from_array(add[index]);
                    let (result_low, result_high) =
                        CarryingMul::carrying_mul_add(lhs, rhs, carry, add);
                    low[index] = result_low.to_array();
                    high[index] = result_high.to_array();
                }
            })
        });
    }};
}

fn bench_word_ops(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    // Full-width values make high halves and carry outputs common, as they are
    // in Barrett/Shoup reduction and CRT accumulation.
    let u32_distribution = Uniform::new_inclusive(u32::MIN, u32::MAX).unwrap();
    let u64_distribution = Uniform::new_inclusive(u64::MIN, u64::MAX).unwrap();
    let u32_inputs = word_inputs(&mut rng, &u32_distribution);
    let u64_inputs = word_inputs(&mut rng, &u64_distribution);

    let mut group = c.benchmark_group("word_ops");
    group.throughput(Throughput::Elements(BATCH_LEN as u64));

    bench_scalar_word_ops!(group, "u32", u32, u32_inputs);
    bench_scalar_word_ops!(group, "u64", u64, u64_inputs);

    #[cfg(feature = "simd")]
    {
        bench_simd_word_ops!(group, "u32x8", u32, 8, u32_inputs);
        bench_simd_word_ops!(group, "u64x4", u64, 4, u64_inputs);
    }

    group.finish();
}

criterion_group!(benches, bench_word_ops);
criterion_main!(benches);
