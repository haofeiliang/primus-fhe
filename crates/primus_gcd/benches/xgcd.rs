// cargo bench -p primus_gcd --bench xgcd

use core::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_gcd::Xgcd;
use rand::distr::{Distribution, Uniform};
use rand::{Rng, SeedableRng, rngs::StdRng};

const DATASET_LEN: usize = 1_000;
const RNG_SEED: u64 = 0x6763_645f_6265_6e63;
const HIGH_MSB_THRESHOLD: u64 = 1 << (u64::BITS - 1);
const MASK_16_BITS: u64 = 0xFFFF;

fn ordered_distinct_pairs<R, D>(rng: &mut R, distribution: &D) -> Vec<(u64, u64)>
where
    R: Rng + ?Sized,
    D: Distribution<u64>,
{
    (0..DATASET_LEN)
        .map(|_| {
            loop {
                let x = distribution.sample(rng);
                let y = distribution.sample(rng);
                if x != y {
                    break (x.max(y), x.min(y));
                }
            }
        })
        .collect()
}

fn bench_primitive_gcd(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(RNG_SEED);

    // Both operands stay below the high-MSB range, exercising the general
    // quotient path and its quot=1/2/3 short-circuits.
    let general_distribution = Uniform::new(0, HIGH_MSB_THRESHOLD).unwrap();
    let general_pairs = ordered_distinct_pairs(&mut rng, &general_distribution);

    // Both operands have their top bit set, exercising the specialized
    // high-MSB paths in xgcd and gcdinv.
    let high_msb_distribution = Uniform::new_inclusive(HIGH_MSB_THRESHOLD, u64::MAX).unwrap();
    let high_msb_pairs = ordered_distinct_pairs(&mut rng, &high_msb_distribution);

    // Even values return None immediately for power-of-two inverses, so keep
    // this dataset odd to measure the nontrivial Newton-lifting path.
    let odd_values: Vec<u64> = general_pairs
        .iter()
        .map(|&(larger, _)| larger | 1)
        .collect();

    let mut group = c.benchmark_group("primitive_gcd/u64");

    // Keep each measured closure explicit so its operation and operand order
    // remain visible. iter_batched excludes input rotation from the timed work.
    group.bench_function(BenchmarkId::new("gcd", "general"), |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(black_box(x).gcd(black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("is_coprime", "general"), |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(black_box(x).is_coprime(black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("xgcd", "general"), |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(u64::xgcd(black_box(x), black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("xgcd", "high_msb"), |b| {
        let mut inputs = high_msb_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(u64::xgcd(black_box(x), black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("gcdinv", "general"), |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(larger, smaller)| black_box(u64::gcdinv(black_box(smaller), black_box(larger))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("gcdinv", "high_msb"), |b| {
        let mut inputs = high_msb_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(larger, smaller)| black_box(u64::gcdinv(black_box(smaller), black_box(larger))),
            BatchSize::SmallInput,
        )
    });

    // Keep both explicit mask arguments opaque to measure the public
    // runtime-mask paths rather than constant-specialized calls.
    group.bench_function(BenchmarkId::new("gcdinv_pow_of_2", "full_width"), |b| {
        let mut inputs = odd_values.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |value| black_box(u64::gcdinv_pow_of_2(black_box(value), black_box(u64::MAX))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("gcdinv_native", "full_width"), |b| {
        let mut inputs = odd_values.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |value| black_box(u64::gcdinv_native(black_box(value))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function(BenchmarkId::new("gcdinv_pow_of_2", "16_bit"), |b| {
        let mut inputs = odd_values.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |value| {
                black_box(u64::gcdinv_pow_of_2(
                    black_box(value),
                    black_box(MASK_16_BITS),
                ))
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_primitive_gcd);
criterion_main!(benches);
