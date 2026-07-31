#![allow(dead_code)]

use std::{hint::black_box, time::Duration};

use criterion::{BatchSize, BenchmarkGroup, Criterion, measurement::Measurement};
use rand::{
    RngExt, SeedableRng,
    distr::{Distribution, Uniform},
    rngs::StdRng,
};

pub const MODULUS_U32: u32 = 1_073_692_673;
pub const MODULUS_U64: u64 = 1_125_899_906_826_241;
pub const POWER_OF_TWO_U32: u32 = 1 << 29;
pub const POWER_OF_TWO_U64: u64 = 1 << 50;

pub const SCALAR_INPUT_COUNT: usize = 1_024;
pub const POLY_LENGTH: usize = 4_096;
pub const SCALING_LENGTHS: [usize; 4] = [256, 1_024, POLY_LENGTH, 16_384];

const RNG_SEED: u64 = 0x6d6f_6475_6c75_735f;

pub fn benchmark_config() -> Criterion {
    Criterion::default()
        .sample_size(30)
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

pub struct ScalarInputs<T> {
    pub canonical: Vec<T>,
    pub full_width: Vec<T>,
    pub rhs: Vec<T>,
    pub addend: Vec<T>,
    pub reduce_once: Vec<T>,
    pub nonzero: Vec<T>,
}

pub struct SliceInputs<T> {
    pub lhs: Vec<T>,
    pub rhs: Vec<T>,
    pub addend: Vec<T>,
    pub reduce_once: Vec<T>,
    pub nonzero: Vec<T>,
}

pub fn scalar_inputs_u32(modulus: u32) -> ScalarInputs<u32> {
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ u64::from(modulus));
    ScalarInputs {
        canonical: values_u32(&mut rng, SCALAR_INPUT_COUNT, 0, modulus),
        full_width: (0..SCALAR_INPUT_COUNT).map(|_| rng.random()).collect(),
        rhs: values_u32(&mut rng, SCALAR_INPUT_COUNT, 0, modulus),
        addend: values_u32(&mut rng, SCALAR_INPUT_COUNT, 0, modulus),
        reduce_once: values_u32(&mut rng, SCALAR_INPUT_COUNT, 0, modulus * 2),
        nonzero: values_u32(&mut rng, SCALAR_INPUT_COUNT, 1, modulus),
    }
}

pub fn scalar_inputs_u64(modulus: u64) -> ScalarInputs<u64> {
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ modulus);
    ScalarInputs {
        canonical: values_u64(&mut rng, SCALAR_INPUT_COUNT, 0, modulus),
        full_width: (0..SCALAR_INPUT_COUNT).map(|_| rng.random()).collect(),
        rhs: values_u64(&mut rng, SCALAR_INPUT_COUNT, 0, modulus),
        addend: values_u64(&mut rng, SCALAR_INPUT_COUNT, 0, modulus),
        reduce_once: values_u64(&mut rng, SCALAR_INPUT_COUNT, 0, modulus * 2),
        nonzero: values_u64(&mut rng, SCALAR_INPUT_COUNT, 1, modulus),
    }
}

pub fn slice_inputs_u32(modulus: u32, len: usize) -> SliceInputs<u32> {
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ u64::from(modulus) ^ len as u64);
    SliceInputs {
        lhs: values_u32(&mut rng, len, 0, modulus),
        rhs: values_u32(&mut rng, len, 0, modulus),
        addend: values_u32(&mut rng, len, 0, modulus),
        reduce_once: values_u32(&mut rng, len, 0, modulus * 2),
        nonzero: values_u32(&mut rng, len, 1, modulus),
    }
}

pub fn slice_inputs_u64(modulus: u64, len: usize) -> SliceInputs<u64> {
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ modulus ^ len as u64);
    SliceInputs {
        lhs: values_u64(&mut rng, len, 0, modulus),
        rhs: values_u64(&mut rng, len, 0, modulus),
        addend: values_u64(&mut rng, len, 0, modulus),
        reduce_once: values_u64(&mut rng, len, 0, modulus * 2),
        nonzero: values_u64(&mut rng, len, 1, modulus),
    }
}

fn values_u32(rng: &mut StdRng, len: usize, low: u32, high: u32) -> Vec<u32> {
    let distribution = Uniform::new(low, high).unwrap();
    (0..len).map(|_| distribution.sample(rng)).collect()
}

fn values_u64(rng: &mut StdRng, len: usize, low: u64, high: u64) -> Vec<u64> {
    let distribution = Uniform::new(low, high).unwrap();
    (0..len).map(|_| distribution.sample(rng)).collect()
}

pub fn bench_unary<T, M, R>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    input: &[T],
    modulus: M,
    operation: impl Fn(M, T) -> R + Copy,
) where
    T: Copy,
    M: Copy,
{
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        let mut input = input.iter().copied().cycle();
        b.iter_batched(
            || input.next().unwrap(),
            |value| black_box(operation(modulus, black_box(value))),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_binary<T, M, R>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, T, T) -> R + Copy,
) where
    T: Copy,
    M: Copy,
{
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        let mut input = lhs.iter().copied().zip(rhs.iter().copied()).cycle();
        b.iter_batched(
            || input.next().unwrap(),
            |(lhs, rhs)| black_box(operation(modulus, black_box(lhs), black_box(rhs))),
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_ternary<T, M, R>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    addend: &[T],
    modulus: M,
    operation: impl Fn(M, T, T, T) -> R + Copy,
) where
    T: Copy,
    M: Copy,
{
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        let mut input = lhs
            .iter()
            .copied()
            .zip(rhs.iter().copied())
            .zip(addend.iter().copied())
            .cycle();
        b.iter_batched(
            || input.next().unwrap(),
            |((lhs, rhs), addend)| {
                black_box(operation(
                    modulus,
                    black_box(lhs),
                    black_box(rhs),
                    black_box(addend),
                ))
            },
            BatchSize::SmallInput,
        )
    });
}

pub fn bench_slice_unary_to<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    input: &[T],
    modulus: M,
    operation: impl Fn(M, &[T], &mut [T]),
) where
    T: Copy + Default,
    M: Copy,
{
    let mut output = vec![T::default(); input.len()];
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| operation(modulus, black_box(input), black_box(&mut output)))
    });
}

pub fn bench_slice_binary_to<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, &[T], &[T], &mut [T]),
) where
    T: Copy + Default,
    M: Copy,
{
    let mut output = vec![T::default(); lhs.len()];
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| {
            operation(
                modulus,
                black_box(lhs),
                black_box(rhs),
                black_box(&mut output),
            )
        })
    });
}

pub fn bench_slice_ternary_to<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    addend: &[T],
    modulus: M,
    operation: impl Fn(M, &[T], &[T], &[T], &mut [T]),
) where
    T: Copy + Default,
    M: Copy,
{
    let mut output = vec![T::default(); lhs.len()];
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| {
            operation(
                modulus,
                black_box(lhs),
                black_box(rhs),
                black_box(addend),
                black_box(&mut output),
            )
        })
    });
}

pub fn bench_slice_scalar_to<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    input: &[T],
    scalar: T,
    modulus: M,
    operation: impl Fn(M, &[T], T, &mut [T]),
) where
    T: Copy + Default,
    M: Copy,
{
    let mut output = vec![T::default(); input.len()];
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| {
            operation(
                modulus,
                black_box(input),
                black_box(scalar),
                black_box(&mut output),
            )
        })
    });
}

pub fn bench_slice_dot_product<T, M, R>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, &[T], &[T]) -> R,
) where
    T: Copy,
    M: Copy,
{
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| black_box(operation(modulus, black_box(lhs), black_box(rhs))))
    });
}
