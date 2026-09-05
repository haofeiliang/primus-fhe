// cargo bench -p primus_decompose --bench decompose
//
// BigUint setup measures integer decomposition precomputation only. RNS
// reconstruction weights belong to primus_glwe_rns parameter construction.

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::{big_integer::BigUintApproxSignedBasis, primitive::ApproxSignedBasis};
use primus_integer::{BigUint, FheUint, multiply_many_values};

type Word = u64;

const COEFFICIENT_COUNT: usize = 4096;
const PRIMITIVE_LOG_BASIS: u32 = 8;
const BIG_LOG_BASIS: u32 = 16;
const MODULI: [Word; 4] = [
    1_125_899_906_826_241,
    1_125_899_906_629_633,
    1_125_899_906_031_617,
    1_125_899_904_679_937,
];

fn big_modulus(limb_count: usize) -> BigUint<Vec<Word>> {
    multiply_many_values(&MODULI[..limb_count])
}

fn primitive_values(modulus: Option<Word>, count: usize) -> Vec<Word> {
    (0..count)
        .map(|index| {
            let value = (index as Word)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0xd1b5_4a32_d192_ed03);
            modulus.map_or(value, |q| value % q)
        })
        .collect()
}

fn big_values(modulus: BigUint<&[Word]>, count: usize) -> Vec<Word> {
    let len = modulus.len();
    let high_mask = Word::MAX >> modulus[len - 1].leading_zeros();
    let mut values = primitive_values(None, count * len);
    for digits in values.chunks_exact_mut(len) {
        // Limit inputs to the modulus bit width, then reduce once: 2^bits < 2Q.
        digits[len - 1] &= high_mask;
        let mut value = BigUint(digits);
        if value.cmp(&modulus).is_ge() {
            let _ = value.sub_assign(&modulus);
        }
    }
    values
}

fn bench_primitive_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/primitive/setup");
    for (label, modulus) in [("native", None), ("explicit_q50", Some(MODULI[0]))] {
        group.bench_function(
            BenchmarkId::new("new", format!("{label}/logB={PRIMITIVE_LOG_BASIS}")),
            |b| {
                b.iter(|| {
                    black_box(ApproxSignedBasis::<Word>::new(
                        black_box(modulus),
                        PRIMITIVE_LOG_BASIS,
                        None,
                    ))
                });
            },
        );
    }
    group.finish();
}

fn bench_primitive_online(c: &mut Criterion) {
    // Native Fourier: exact and truncated, both using the no-copy carry path.
    primitive_online(c, "u64/native", None::<u64>, 8, None);
    primitive_online(c, "u64/native", None::<u64>, 8, Some(3));
    // Explicit moduli: adjustment with and without an initial rounding carry.
    primitive_online(c, "u64/q50", Some(MODULI[0]), 8, None);
    primitive_online(c, "u64/q50", Some(MODULI[0]), 10, None);
    // Representative NTT key-switching and external-product decompositions.
    primitive_online(c, "u32/q27", Some(132_120_577u32), 2, Some(13));
    primitive_online(c, "u32/q27", Some(132_120_577u32), 7, Some(3));
}

fn primitive_online<T: FheUint>(
    c: &mut Criterion,
    label: &str,
    modulus: Option<T>,
    log_basis: u32,
    retained: Option<usize>,
) {
    let mut group = c.benchmark_group("decompose/primitive/online");
    let basis = ApproxSignedBasis::new(modulus, log_basis, retained);
    let value = T::as_from(primitive_values(None, 1)[0]);
    let value = modulus.map_or(value, |q| value % q);
    group.bench_function(
        BenchmarkId::new(
            "scalar_to",
            format!(
                "{label}/logB={log_basis}/L={}/drop={}",
                basis.decompose_length(),
                basis.drop_bits()
            ),
        ),
        |b| {
            b.iter(|| {
                let (adjusted, mut carry) = basis.init_value_carry(black_box(value));
                let mut digit = T::ZERO;
                for decomposer in basis.decomposer_iter() {
                    decomposer.decompose_to(adjusted, &mut digit, &mut carry);
                    black_box(digit);
                }
                black_box(carry)
            })
        },
    );
    for count in [1024, 4096] {
        let case = format!(
            "{label}/logB={log_basis}/L={}/drop={}/N={count}",
            basis.decompose_length(),
            basis.drop_bits(),
        );
        let values: Vec<T> = primitive_values(None, count)
            .into_iter()
            .map(|value| {
                let value = T::as_from(value);
                modulus.map_or(value, |q| value % q)
            })
            .collect();
        let mut decomposed = vec![T::ZERO; count];
        let mut carries = vec![false; count];
        group.throughput(Throughput::Elements(count as u64));
        // Select the initialization path outside the timed coefficient loops.
        if basis.modulus_is_power_of_2() {
            group.bench_function(BenchmarkId::new("batch_borrowed", &case), |b| {
                b.iter(|| {
                    basis.init_carry_slice(black_box(&values), black_box(&mut carries));
                    for decomposer in basis.decomposer_iter() {
                        decomposer.decompose_slice_to(
                            black_box(&values),
                            black_box(&mut decomposed),
                            black_box(&mut carries),
                        );
                        black_box(&decomposed);
                    }
                });
            });
        } else {
            let mut adjusted = vec![T::ZERO; count];
            group.bench_function(BenchmarkId::new("batch_to", &case), |b| {
                b.iter(|| {
                    basis.init_value_carry_slice_to(
                        black_box(&values),
                        black_box(&mut adjusted),
                        black_box(&mut carries),
                    );
                    for decomposer in basis.decomposer_iter() {
                        decomposer.decompose_slice_to(
                            black_box(&adjusted),
                            black_box(&mut decomposed),
                            black_box(&mut carries),
                        );
                        black_box(&decomposed);
                    }
                });
            });
        }
    }
    group.finish();
}

fn bench_big_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/big/setup");
    for limb_count in [1, 2, 4] {
        let modulus = big_modulus(limb_count);
        group.bench_function(
            BenchmarkId::new("new", format!("{limb_count}_limbs/logB={BIG_LOG_BASIS}")),
            |b| {
                b.iter(|| {
                    black_box(BigUintApproxSignedBasis::new(
                        black_box(modulus.view()),
                        BIG_LOG_BASIS,
                        None,
                    ))
                });
            },
        );
    }
    group.finish();
}

fn bench_big_online(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/big/online");
    for limb_count in [1, 2, 4] {
        let modulus = big_modulus(limb_count);
        let basis = BigUintApproxSignedBasis::new(modulus.view(), BIG_LOG_BASIS, None);
        let case = format!(
            "{limb_count}_limbs/logB={BIG_LOG_BASIS}/levels={}",
            basis.decompose_length()
        );

        let scalar_value = big_values(modulus.view(), 1);
        group.bench_function(BenchmarkId::new("scalar_allocating", &case), |b| {
            b.iter(|| {
                let value = BigUint(black_box(scalar_value.as_slice()));
                let (adjusted, mut carry) = basis.init_value_carry(&value);
                for decomposer in basis.decomposer_iter() {
                    let (decomposed, next_carry) = decomposer.decompose(&adjusted, carry);
                    carry = next_carry;
                    black_box(decomposed);
                }
                black_box(carry)
            });
        });

        let mut scalar_adjusted = vec![0; limb_count];
        let mut scalar_decomposed = vec![0; limb_count];
        let mut scalar_carry = [false];
        group.bench_function(BenchmarkId::new("scalar_to", &case), |b| {
            b.iter(|| {
                basis.init_value_carry_slice_to(
                    black_box(&scalar_value),
                    black_box(&mut scalar_adjusted),
                    black_box(&mut scalar_carry),
                );
                let mut carry = scalar_carry[0];
                for decomposer in basis.decomposer_iter() {
                    decomposer.decompose_to(
                        black_box(&scalar_adjusted),
                        black_box(&mut scalar_decomposed),
                        black_box(&mut carry),
                    );
                    black_box(&scalar_decomposed);
                }
                black_box(carry)
            });
        });

        let values = big_values(modulus.view(), COEFFICIENT_COUNT);
        let mut adjusted = vec![0; values.len()];
        let mut decomposed = vec![0; values.len()];
        let mut carries = vec![false; COEFFICIENT_COUNT];
        group.bench_function(
            BenchmarkId::new(format!("batch_to/N={COEFFICIENT_COUNT}"), &case),
            |b| {
                b.iter(|| {
                    basis.init_value_carry_slice_to(
                        black_box(&values),
                        black_box(&mut adjusted),
                        black_box(&mut carries),
                    );
                    for decomposer in basis.decomposer_iter() {
                        decomposer.decompose_slice_to(
                            black_box(&adjusted),
                            black_box(&mut decomposed),
                            black_box(&mut carries),
                        );
                        black_box(&decomposed);
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_big_initialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/big/initialization");

    for (limb_count, log_basis, retained) in big_batch_cases() {
        let modulus = big_modulus(limb_count);
        let basis = BigUintApproxSignedBasis::new(modulus.view(), log_basis, retained);
        let values = big_values(modulus.view(), COEFFICIENT_COUNT);
        let mut adjusted = vec![0; values.len()];
        let mut carries = vec![false; COEFFICIENT_COUNT];
        let case = format!(
            "{limb_count}_limbs/logB={log_basis}/L={}/drop={}/N={COEFFICIENT_COUNT}",
            basis.decompose_length(),
            basis.drop_bits()
        );
        group.throughput(Throughput::Elements(COEFFICIENT_COUNT as u64));
        group.bench_function(BenchmarkId::new("batch_to", &case), |b| {
            b.iter(|| {
                basis.init_value_carry_slice_to(
                    black_box(&values),
                    black_box(&mut adjusted),
                    black_box(&mut carries),
                );
                black_box(&adjusted);
                black_box(&carries);
            });
        });
        group.bench_function(BenchmarkId::new("batch_assign", &case), |b| {
            // Each input must be canonical again: repeated in-place adjustment
            // is not valid. Reset outside timing, as CRT compose does upstream.
            b.iter_batched_ref(
                || values.clone(),
                |input| {
                    basis.init_value_carry_slice_assign(black_box(input), black_box(&mut carries));
                    black_box(&*input);
                    black_box(&carries);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn big_batch_cases() -> [(usize, u32, Option<usize>); 4] {
    // 50/100/200-bit moduli: one limb; no drop with crossing windows;
    // multiple limbs with rounding; retained levels starting in limb 1.
    [
        (1, 16, None),
        (2, 20, None),
        (4, 16, None),
        (2, 17, Some(1)),
    ]
}

fn bench_big_unsigned(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/big/unsigned");
    for (limb_count, log_basis, retained) in big_batch_cases() {
        let modulus = big_modulus(limb_count);
        let basis = BigUintApproxSignedBasis::new(modulus.view(), log_basis, retained);
        for count in [1024, 4096] {
            let values = big_values(modulus.view(), count);
            let mut adjusted = vec![0; values.len()];
            let mut digits = vec![0; count];
            let mut carries = vec![false; count];
            let case = format!(
                "{limb_count}_limbs/logB={log_basis}/L={}/drop={}/N={count}",
                basis.decompose_length(),
                basis.drop_bits()
            );
            group.throughput(Throughput::Elements(count as u64));
            group.bench_function(BenchmarkId::new("batch_to", case), |b| {
                b.iter(|| {
                    basis.init_value_carry_slice_to(
                        black_box(&values),
                        black_box(&mut adjusted),
                        black_box(&mut carries),
                    );
                    for decomposer in basis.decomposer_iter() {
                        decomposer.unsigned_decompose_slice_to(
                            black_box(&adjusted),
                            black_box(&mut digits),
                            black_box(&mut carries),
                        );
                        black_box(&digits);
                    }
                });
            });
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_primitive_setup,
    bench_primitive_online,
    bench_big_setup,
    bench_big_online,
    bench_big_initialization,
    bench_big_unsigned,
);
criterion_main!(benches);
