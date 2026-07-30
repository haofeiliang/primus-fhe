use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_gcd::Xgcd;
use rand::distr::{Distribution, Uniform};
use rand::{Rng, SeedableRng, rngs::StdRng};

type ValueT = u64;

const DATASET_LEN: usize = 1_000;
const RNG_SEED: u64 = 0x6763_645f_6265_6e63;
const GENERAL_INPUT_UPPER_BOUND: ValueT = ValueT::MAX >> 1;
const HIGH_MSB_INPUT_LOWER_BOUND: ValueT = GENERAL_INPUT_UPPER_BOUND + 1;
const SMALL_POWER_OF_TWO_MASK: ValueT = 0xFFFF;

fn ordered_distinct_pairs<R, D>(rng: &mut R, distribution: &D) -> Vec<(ValueT, ValueT)>
where
    R: Rng + ?Sized,
    D: Distribution<ValueT>,
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

fn bench_gcd(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(RNG_SEED);

    // Both operands stay below the high-MSB range, exercising the general
    // quotient path and its quot=1/2/3 short-circuits.
    let general_distribution = Uniform::new(0, GENERAL_INPUT_UPPER_BOUND).unwrap();
    let general_pairs = ordered_distinct_pairs(&mut rng, &general_distribution);

    // Both operands have their top bit set, exercising the specialized
    // high-MSB paths in xgcd and gcdinv.
    let high_msb_distribution =
        Uniform::new_inclusive(HIGH_MSB_INPUT_LOWER_BOUND, ValueT::MAX).unwrap();
    let high_msb_pairs = ordered_distinct_pairs(&mut rng, &high_msb_distribution);

    // Even values return None immediately for power-of-two inverses, so keep
    // this dataset odd to measure the nontrivial Newton-lifting path.
    let odd_values: Vec<ValueT> = general_pairs
        .iter()
        .map(|&(larger, _)| larger | 1)
        .collect();

    debug_assert_eq!(general_pairs.len(), DATASET_LEN);
    debug_assert!(
        general_pairs
            .iter()
            .all(|&(larger, smaller)| { larger > smaller && larger < GENERAL_INPUT_UPPER_BOUND })
    );
    debug_assert_eq!(high_msb_pairs.len(), DATASET_LEN);
    debug_assert!(
        high_msb_pairs.iter().all(|&(larger, smaller)| {
            larger > smaller && smaller >= HIGH_MSB_INPUT_LOWER_BOUND
        })
    );
    debug_assert_eq!(odd_values.len(), DATASET_LEN);
    debug_assert!(odd_values.iter().all(|&value| value & 1 == 1));

    let mut group = c.benchmark_group("primitive_gcd");

    // Keep these measured closures explicit. Factoring them through a generic
    // helper changes inlining and code layout enough to skew nanosecond-scale
    // results. iter_batched excludes input rotation from the timed routine.
    group.bench_function("gcd", |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(black_box(x).gcd(black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("is_coprime", |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(black_box(x).is_coprime(black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("xgcd", |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(ValueT::xgcd(black_box(x), black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("xgcd_msb", |b| {
        let mut inputs = high_msb_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(ValueT::xgcd(black_box(x), black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv", |b| {
        let mut inputs = general_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(larger, smaller)| black_box(ValueT::gcdinv(black_box(smaller), black_box(larger))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv_msb", |b| {
        let mut inputs = high_msb_pairs.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(larger, smaller)| black_box(ValueT::gcdinv(black_box(smaller), black_box(larger))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv_pow_of_2 (mask=MAX)", |b| {
        let mut inputs = odd_values.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |value| {
                black_box(ValueT::gcdinv_pow_of_2(
                    black_box(value),
                    black_box(ValueT::MAX),
                ))
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv_native", |b| {
        let mut inputs = odd_values.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |value| black_box(ValueT::gcdinv_native(black_box(value))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv_pow_of_2 (mask=0xFFFF)", |b| {
        let mut inputs = odd_values.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |value| {
                black_box(ValueT::gcdinv_pow_of_2(
                    black_box(value),
                    black_box(SMALL_POWER_OF_TWO_MASK),
                ))
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_gcd);
criterion_main!(benches);
