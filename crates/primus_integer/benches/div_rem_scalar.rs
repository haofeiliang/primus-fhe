mod support;

use core::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_integer::{DivRemScalar, DivWide};
use rand::distr::Uniform;
use rand::{SeedableRng, rngs::StdRng};

use support::{RNG_SEED, sampled_values};

const LIMB_COUNTS: [usize; 2] = [2, 8];
const U128_HALF_WORD_DIVISOR: u128 = 0xdead_beef_cafe_babe;
const U128_FULL_WIDTH_DIVISOR: u128 = (1u128 << 96) | 0xc0ff_ee15_dead_beef;

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

    // u128 has separate half-word and Knuth-D kernels because no wider
    // primitive integer is available. Two and eight limbs expose both the
    // fixed setup cost and the per-limb cost of each kernel.
    let distribution = Uniform::new_inclusive(u128::MIN, u128::MAX).unwrap();
    for limb_count in LIMB_COUNTS {
        let dividend = sampled_values(&mut rng, &distribution, limb_count);
        let mut quotient = vec![0u128; limb_count];

        group.throughput(Throughput::Elements(limb_count as u64));
        group.bench_function(
            BenchmarkId::new("u128_half_word", format!("{limb_count}_limbs")),
            |b| {
                b.iter(|| {
                    let remainder = u128::div_rem_scalar(
                        black_box(dividend.as_slice()),
                        black_box(U128_HALF_WORD_DIVISOR),
                        black_box(quotient.as_mut_slice()),
                    );
                    black_box(remainder)
                })
            },
        );

        group.bench_function(
            BenchmarkId::new("u128_full_width", format!("{limb_count}_limbs")),
            |b| {
                b.iter(|| {
                    let remainder = u128::div_rem_scalar(
                        black_box(dividend.as_slice()),
                        black_box(U128_FULL_WIDTH_DIVISOR),
                        black_box(quotient.as_mut_slice()),
                    );
                    black_box(remainder)
                })
            },
        );
    }

    let lo = 0xfedc_ba98_7654_3210_0123_4567_89ab_cdef;
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("u128_div_wide", "half_word"), |b| {
        b.iter(|| {
            black_box(u128::div_wide(
                black_box(lo),
                black_box(U128_HALF_WORD_DIVISOR - 1),
                black_box(U128_HALF_WORD_DIVISOR),
            ))
        })
    });
    group.bench_function(BenchmarkId::new("u128_div_wide", "full_width"), |b| {
        b.iter(|| {
            black_box(u128::div_wide(
                black_box(lo),
                black_box(U128_FULL_WIDTH_DIVISOR - 1),
                black_box(U128_FULL_WIDTH_DIVISOR),
            ))
        })
    });

    group.finish();
}

criterion_group!(benches, bench_div_rem_scalar);
criterion_main!(benches);
