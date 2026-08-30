use core::hint::black_box;

use criterion::{BenchmarkGroup, Throughput, measurement::Measurement};

pub const MODULUS_U64: u64 = 1_125_899_906_826_241;
pub const INPUT_COUNT: usize = 1_024;

pub fn bench_binary<T, M>(
    group: &mut BenchmarkGroup<'_, impl Measurement>,
    name: &str,
    lhs: &[T],
    rhs: &[T],
    modulus: M,
    operation: impl Fn(M, T, T) -> T,
) where
    T: Copy + Default,
    M: Copy,
{
    let mut output = vec![T::default(); lhs.len()];
    group.throughput(Throughput::Elements(lhs.len() as u64));
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter(|| {
            output
                .iter_mut()
                .zip(lhs)
                .zip(rhs)
                .for_each(|((output, &lhs), &rhs)| *output = operation(modulus, lhs, rhs));
            black_box(&mut output);
        })
    });
}
