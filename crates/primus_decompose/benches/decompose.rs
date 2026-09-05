// cargo bench -p primus_decompose --bench decompose
//
// Compare scalar and SIMD builds with the same nightly toolchain:
// cargo +nightly bench -p primus_decompose --bench decompose -- --save-baseline nightly-scalar
// cargo +nightly bench -p primus_decompose --bench decompose --features simd -- --baseline nightly-scalar

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_decompose::{big_integer::BigUintApproxSignedBasis, primitive::ApproxSignedBasis};
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_rns::RNSBase;

type Word = u64;
type Modulus = BarrettModulus<Word>;
type Base = RNSBase<Word, Modulus>;

const COEFFICIENT_COUNT: usize = 4096;
const PRIMITIVE_LOG_BASIS: u32 = 8;
const BIG_LOG_BASIS: u32 = 16;
const MODULI: [Word; 4] = [
    1_125_899_906_826_241,
    1_125_899_906_629_633,
    1_125_899_906_031_617,
    1_125_899_904_679_937,
];

fn rns_base(limb_count: usize) -> Base {
    let moduli: Vec<_> = MODULI[..limb_count]
        .iter()
        .copied()
        .map(Modulus::new)
        .collect();
    RNSBase::new(&moduli).unwrap()
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

fn big_values(base: &Base, count: usize) -> Vec<Word> {
    let mut residues = vec![0; base.moduli_count() * count];
    for (modulus_index, modulus) in base.moduli().iter().enumerate() {
        for value_index in 0..count {
            residues[modulus_index * count + value_index] = (value_index as Word)
                .wrapping_mul(1_000_003)
                .wrapping_add((modulus_index as Word + 1) * 17)
                % modulus.value();
        }
    }

    let mut values = vec![0; base.big_uint_value_len() * count];
    let mut scratch = vec![0; base.moduli_count()];
    base.compose_big_uint_values_to(&residues, &mut values, count, &mut scratch);
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
    let mut group = c.benchmark_group("decompose/primitive/online");
    for (label, modulus) in [("native", None), ("explicit_q50", Some(MODULI[0]))] {
        let basis = ApproxSignedBasis::<Word>::new(modulus, PRIMITIVE_LOG_BASIS, None);
        let case = format!(
            "{label}/logB={PRIMITIVE_LOG_BASIS}/levels={}",
            basis.decompose_length()
        );

        let value = primitive_values(modulus, 1)[0];
        group.bench_function(BenchmarkId::new("scalar_to", &case), |b| {
            b.iter(|| {
                let (adjusted, mut carry) = basis.init_value_carry(black_box(value));
                let mut decomposed = 0;
                for decomposer in basis.decomposer_iter() {
                    decomposer.decompose_to(adjusted, &mut decomposed, &mut carry);
                    black_box(decomposed);
                }
                black_box(carry)
            });
        });

        let values = primitive_values(modulus, COEFFICIENT_COUNT);
        let mut adjusted = vec![0; COEFFICIENT_COUNT];
        let mut decomposed = vec![0; COEFFICIENT_COUNT];
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

fn bench_big_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose/big/setup");
    for limb_count in [1, 2, 4] {
        let base = rns_base(limb_count);
        group.bench_function(
            BenchmarkId::new("new", format!("{limb_count}_limbs/logB={BIG_LOG_BASIS}")),
            |b| {
                b.iter(|| {
                    black_box(BigUintApproxSignedBasis::new(
                        black_box(&base),
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
        let base = rns_base(limb_count);
        let basis = BigUintApproxSignedBasis::new(&base, BIG_LOG_BASIS, None);
        let case = format!(
            "{limb_count}_limbs/logB={BIG_LOG_BASIS}/levels={}",
            basis.decompose_length()
        );

        let scalar_value = big_values(&base, 1);
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

        let values = big_values(&base, COEFFICIENT_COUNT);
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

    for limb_count in [1, 2, 4] {
        let base = rns_base(limb_count);
        let basis = BigUintApproxSignedBasis::new(&base, BIG_LOG_BASIS, None);
        let values = big_values(&base, COEFFICIENT_COUNT);
        let mut adjusted = vec![0; values.len()];
        let mut carries = vec![false; COEFFICIENT_COUNT];
        group.bench_function(
            BenchmarkId::new(
                format!("batch_to/N={COEFFICIENT_COUNT}"),
                format!("{limb_count}_limbs"),
            ),
            |b| {
                b.iter(|| {
                    basis.init_value_carry_slice_to(
                        black_box(&values),
                        black_box(&mut adjusted),
                        black_box(&mut carries),
                    );
                    black_box(&adjusted);
                    black_box(&carries);
                });
            },
        );
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
);
criterion_main!(benches);
