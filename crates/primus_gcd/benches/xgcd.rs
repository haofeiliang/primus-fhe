use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use primus_gcd::Xgcd;
use rand::distr::{Distribution, Uniform};
use rand::{Rng, SeedableRng, rngs::StdRng};

type ValueT = u64;
const DATASET_LEN: usize = 1_000;

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
    let mut rng = StdRng::seed_from_u64(0x6763_645f_6265_6e63);

    // Low-MSB inputs: `[0, MAX>>1)` exercises the general `quot = u3 / v3`
    // path and the lower quot=1/2/3 short-circuits.
    let distr_lo = Uniform::new(0, ValueT::MAX >> 1).unwrap();
    let data = ordered_distinct_pairs(&mut rng, &distr_lo);

    // High-MSB inputs: `[MAX>>1 + 1, MAX]` triggers the "both operands have
    // top bit set" / "second MSB set" fast paths and lets us compare their
    // throughput against the general division path above.
    let distr_hi = Uniform::new_inclusive((ValueT::MAX >> 1) + 1, ValueT::MAX).unwrap();
    let data_msb = ordered_distinct_pairs(&mut rng, &distr_hi);

    let mut group = c.benchmark_group("primitive_gcd");

    group.bench_function("gcd", |b| {
        let mut inputs = data.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(black_box(x).gcd(black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("is_coprime", |b| {
        let mut inputs = data.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(black_box(x).is_coprime(black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("xgcd", |b| {
        let mut inputs = data.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(ValueT::xgcd(black_box(x), black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("xgcd_msb", |b| {
        let mut inputs = data_msb.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(x, y)| black_box(ValueT::xgcd(black_box(x), black_box(y))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv", |b| {
        let mut inputs = data.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(larger, smaller)| black_box(ValueT::gcdinv(black_box(smaller), black_box(larger))),
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv_msb", |b| {
        let mut inputs = data_msb.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |(larger, smaller)| black_box(ValueT::gcdinv(black_box(smaller), black_box(larger))),
            BatchSize::SmallInput,
        )
    });

    // Odd low-MSB inputs for gcdinv_pow_of_2 / gcdinv_native (even inputs
    // return None immediately, which skews the measurement).
    let data_odd: Vec<ValueT> = data.iter().map(|&(x, _)| x | 1).collect();

    group.bench_function("gcdinv_pow_of_2 (mask=MAX)", |b| {
        let mut inputs = data_odd.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |a| {
                black_box(ValueT::gcdinv_pow_of_2(
                    black_box(a),
                    black_box(ValueT::MAX),
                ))
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("gcdinv_native", |b| {
        let mut inputs = data_odd.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |a| black_box(ValueT::gcdinv_native(black_box(a))),
            BatchSize::SmallInput,
        )
    });

    // gcdinv_pow_of_2 with a smaller power-of-two modulus (16-bit).
    group.bench_function("gcdinv_pow_of_2 (mask=0xFFFF)", |b| {
        let mut inputs = data_odd.iter().copied().cycle();
        b.iter_batched(
            || inputs.next().unwrap(),
            |a| black_box(ValueT::gcdinv_pow_of_2(black_box(a), black_box(0xFFFF))),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_gcd);
criterion_main!(benches);
