use core::hint::black_box;

use criterion::{BenchmarkGroup, measurement::Measurement};

pub const MODULUS_U32: u32 = 1_073_692_673;
pub const MODULUS_U64: u64 = 1_125_899_906_826_241;

pub const POLY_LENGTH: usize = 4_096;
pub const SCALING_LENGTHS: [usize; 4] = [256, 1_024, POLY_LENGTH, 16_384];

pub fn bench_binary_to<T, M>(
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

pub fn bench_dot_product<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, &[T], &[T]) -> T,
) where
    M: Copy,
{
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| black_box(operation(modulus, black_box(lhs), black_box(rhs))))
    });
}
