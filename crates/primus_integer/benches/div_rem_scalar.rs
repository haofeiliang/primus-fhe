mod support;

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::DivRemScalar;
use rand::distr::Uniform;
use rand::{SeedableRng, rngs::StdRng};

use support::{RNG_SEED, sampled_values};

const LIMB_COUNTS: [usize; 2] = [2, 8];

macro_rules! bench_barrett_division {
    ($group:expr, $type_name:literal, $ty:ty, $divisor:expr) => {{
        let dividend = [0 as $ty, 0 as $ty, 1 as $ty];
        let mut quotient = [0 as $ty; 3];
        $group.throughput(Throughput::Elements(dividend.len() as u64));
        $group.bench_function(BenchmarkId::new("barrett_reciprocal", $type_name), |b| {
            b.iter(|| {
                let remainder = <$ty>::div_rem_scalar(
                    black_box(&dividend),
                    black_box($divisor),
                    black_box(&mut quotient),
                );
                black_box(remainder)
            })
        });
    }};
}

fn bench_div_rem_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("div_rem_scalar");

    // Barrett precomputation divides 2^(2*BITS) by a word-sized modulus.
    bench_barrett_division!(group, "u32", u32, 1_056_866_017u32);
    bench_barrett_division!(group, "u64", u64, 1_125_899_906_826_241u64);

    // BFV plaintext scaling divides a dense RNS modulus product by a small
    // plaintext modulus. Two and eight limbs cover small and deep RNS bases.
    const PLAINTEXT_MODULUS: u64 = 65_537;
    let mut rng = StdRng::seed_from_u64(RNG_SEED ^ 0x6469_7669_7369_6f6e);
    let distribution = Uniform::new_inclusive(u64::MIN, u64::MAX).unwrap();
    for limb_count in LIMB_COUNTS {
        let dividend = sampled_values(&mut rng, &distribution, limb_count);
        let mut quotient = vec![0u64; limb_count];
        let case = format!("u64/{limb_count}_limbs");

        group.throughput(Throughput::Elements(limb_count as u64));
        group.bench_function(BenchmarkId::new("plaintext_scale", case), |b| {
            b.iter(|| {
                let remainder = u64::div_rem_scalar(
                    black_box(dividend.as_slice()),
                    black_box(PLAINTEXT_MODULUS),
                    black_box(quotient.as_mut_slice()),
                );
                black_box(remainder)
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_div_rem_scalar);
criterion_main!(benches);
