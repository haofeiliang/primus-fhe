use core::hint::black_box;

use criterion::{BatchSize, BenchmarkGroup, measurement::Measurement};

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
    T: Copy,
    M: Copy,
{
    assert_eq!(lhs.len(), rhs.len(), "scalar benchmark length mismatch");
    assert!(!lhs.is_empty(), "scalar benchmark inputs must be non-empty");

    let mut inputs = lhs.iter().copied().zip(rhs.iter().copied()).cycle();
    group.bench_function(name, |b| {
        let modulus = black_box(modulus);
        b.iter_batched(
            || {
                inputs
                    .next()
                    .expect("scalar benchmark inputs must be non-empty")
            },
            |(lhs, rhs)| black_box(operation(modulus, black_box(lhs), black_box(rhs))),
            BatchSize::SmallInput,
        )
    });
}
