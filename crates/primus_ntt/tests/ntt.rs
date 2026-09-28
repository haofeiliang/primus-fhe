use core::fmt::Debug;

use num_traits::{ConstOne, ConstZero};
use primus_integer::{AsFrom, FheUint};
use primus_modulus::BarrettModulus;
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable, UintNttTable};
use primus_reduce::FieldContext;

const N: usize = 64;
const LOG_N: u32 = N.trailing_zeros();

// Small direct evaluation fixes root choice and bit-reversed output order
// independently of both NTT implementations. All arithmetic fits ordinary u64.
#[test]
fn constructors_and_small_transforms_match_polynomial_evaluation() {
    fn check<Table: NttTable>(modulus: impl FieldContext<Table::ValueT>)
    where
        Table::ValueT: Into<u64>,
    {
        assert!(matches!(
            Table::new(0, modulus),
            Err(primus_ntt::NttError::PolynomialLengthTooSmall)
        ));
        let pow = |base: u64, exponent: usize| (0..exponent).fold(1, |value, _| value * base % 17);
        for log_n in [1, 3] {
            let table = Table::new(log_n, modulus).unwrap();
            let n = table.poly_length();
            // For power-of-two N, root^N = -1 establishes order exactly 2N.
            let root = (2..17).find(|&root| pow(root, n) == 16).unwrap();
            let input: Vec<_> = (0..n).map(|i| (3 * i as u64 + 1) % 17).collect();
            let expected: Vec<_> = (0..n)
                .map(|i| {
                    let reversed = i.reverse_bits() >> (usize::BITS - log_n);
                    let point = pow(root, 2 * reversed + 1);
                    input
                        .iter()
                        .rev()
                        .fold(0, |value, &coefficient| (value * point + coefficient) % 17)
                })
                .collect();
            let mut actual: Vec<_> = input.iter().map(|&x| Table::ValueT::as_from(x)).collect();
            table.transform_slice(&mut actual);
            assert_eq!(
                actual.iter().copied().map(Into::into).collect::<Vec<u64>>(),
                expected
            );
            // The inverse consumes the oracle, so forward/inverse sign or scale
            // errors cannot cancel merely because the transforms round-trip.
            let mut inverse: Vec<_> = expected
                .iter()
                .map(|&x| Table::ValueT::as_from(x))
                .collect();
            table.inverse_transform_slice(&mut inverse);
            assert_eq!(
                inverse.into_iter().map(Into::into).collect::<Vec<u64>>(),
                input
            );
        }
    }
    check::<U32NttTable>(BarrettModulus::new(17u32));
    check::<UintNttTable<u32>>(BarrettModulus::new(17u32));
    check::<U64NttTable>(BarrettModulus::new(17u64));
    check::<UintNttTable<u64>>(BarrettModulus::new(17u64));
}

// Nonconstant coefficients expose root/permutation errors; callers also insert q-1.
fn deterministic_u32_input(n: usize, modulus: u32) -> Vec<u32> {
    (0..n)
        .map(|i| {
            let i = i as u32;
            (17 * i * i + 31 * i + 7) % modulus
        })
        .collect()
}

fn deterministic_u64_input(n: usize, modulus: u64) -> Vec<u64> {
    (0..n)
        .map(|i| {
            let i = i as u64;
            (17 * i * i + 31 * i + 7) % modulus
        })
        .collect()
}

// Differential checks exercise the runtime-selected specialized kernel against
// the portable generic transform, including inverse normalization.
fn assert_transform_matches_reference<Value, Table, Reference>(
    table: &Table,
    reference: &Reference,
    input: &[Value],
) where
    Value: FheUint + Debug,
    Table: NttTable<ValueT = Value>,
    Reference: NttTable<ValueT = Value>,
{
    let mut actual = input.to_vec();
    let mut expected = input.to_vec();

    table.transform_slice(&mut actual);
    reference.transform_slice(&mut expected);
    assert_eq!(actual, expected, "forward transform mismatch");

    table.inverse_transform_slice(&mut actual);
    reference.inverse_transform_slice(&mut expected);
    assert_eq!(actual, input, "specialized NTT did not round-trip");
    assert_eq!(expected, input, "generic NTT did not round-trip");
}

// Build the signed coefficient monomial before using the full transform as
// an oracle for the direct root/grouping shortcuts.
fn assert_monomial<Table>(table: &Table, coeff: Table::ValueT, degree: usize)
where
    Table: MonomialNttTable,
    Table::ValueT: Debug,
{
    let n = table.poly_length();
    let modulus = table.modulus();
    let reduced_degree = degree & (2 * n - 1);
    let reduced_coeff = if reduced_degree < n || coeff == Table::ValueT::ZERO {
        coeff
    } else {
        modulus - coeff
    };

    let mut expected = vec![Table::ValueT::ZERO; n];
    expected[reduced_degree & (n - 1)] = reduced_coeff;
    table.transform_slice(&mut expected);

    // Start dirty so the zero-coefficient fast path must overwrite the output.
    let mut actual = vec![Table::ValueT::ONE; n];
    table.transform_monomial(coeff, degree, &mut actual);
    assert_eq!(actual, expected, "monomial transform mismatch");
}

fn assert_monomial_suite<Table>(table: &Table, nontrivial_coeff: Table::ValueT)
where
    Table: MonomialNttTable,
    Table::ValueT: Debug,
{
    let n = table.poly_length();
    let coefficients = [
        Table::ValueT::ZERO,
        Table::ValueT::ONE,
        table.modulus() - Table::ValueT::ONE,
        nontrivial_coeff,
    ];

    // Constant/negation boundaries, general odd degrees, and grouped even degrees.
    for degree in [0, n, 2 * n, 3 * n, n / 3, n + 37, 6, 12, 2 * n - 6] {
        for &coeff in &coefficients {
            assert_monomial(table, coeff, degree);
        }
    }

    // Both power-of-two fast paths: roots for 2^s and inverse roots for 2N - 2^s.
    for shift in 0..table.poly_length().trailing_zeros() {
        for degree in [1usize << shift, 2 * n - (1usize << shift)] {
            for &coeff in &coefficients {
                assert_monomial(table, coeff, degree);
            }
        }
    }
}

// U32 has one modulus-width kernel. Keep scalar fallback, the SIMD threshold,
// and multiple vector blocks, using q near the lazy 4q word limit.
const U32_Q: u32 = 1_073_692_673;
const U32_LENGTHS: [usize; 3] = [16, 32, 64];

#[test]
fn u32_transform_matches_generic_reference() {
    let q = U32_Q;
    let modulus = BarrettModulus::new(q);
    for n in U32_LENGTHS {
        let table = U32NttTable::new(n.trailing_zeros(), modulus).unwrap();
        let reference = UintNttTable::<u32>::new(n.trailing_zeros(), modulus).unwrap();
        let mut input = deterministic_u32_input(n, q);
        for (i, value) in input.iter_mut().enumerate().step_by(3) {
            *value = q - 1 - i as u32;
        }
        let mut guarded = vec![u32::MAX; n + 2];
        guarded[1..n + 1].copy_from_slice(&input);
        let actual = &mut guarded[1..n + 1];
        let mut expected = input.clone();
        table.transform_slice(actual);
        reference.transform_slice(&mut expected);
        assert_eq!(actual, expected, "forward mismatch for q={q}, n={n}");
        table.inverse_transform_slice(actual);
        assert_eq!(actual, input, "roundtrip mismatch for q={q}, n={n}");
        assert_eq!((guarded[0], guarded[n + 1]), (u32::MAX, u32::MAX));
    }
}

#[test]
fn u32_lazy_transforms_match_generic_reference() {
    let q = U32_Q;
    let modulus = BarrettModulus::new(q);
    for n in U32_LENGTHS {
        let table = U32NttTable::new(n.trailing_zeros(), modulus).unwrap();
        let reference = UintNttTable::<u32>::new(n.trailing_zeros(), modulus).unwrap();
        for inverse in [false, true] {
            let bound = if inverse { 2 * q } else { 4 * q };
            let mut guarded = vec![u32::MAX; n + 2];
            let actual = &mut guarded[1..n + 1];
            for (i, value) in actual.iter_mut().enumerate() {
                *value = match i % 4 {
                    0 => bound - 1 - i as u32,
                    1 => q,
                    2 => 0,
                    _ => (17 * i as u32 + 7) % bound,
                };
            }
            let mut expected: Vec<_> = actual.iter().map(|&v| v % q).collect();
            if inverse {
                table.lazy_inverse_transform_slice(actual);
                reference.inverse_transform_slice(&mut expected);
            } else {
                table.lazy_transform_slice(actual);
                reference.transform_slice(&mut expected);
            }
            assert!(actual.iter().all(|&value| value < bound));
            for (&actual, expected) in actual.iter().zip(expected) {
                assert_eq!(
                    actual % q,
                    expected,
                    "lazy mismatch for q={q}, n={n}, inverse={inverse}"
                );
            }
            assert_eq!((guarded[0], guarded[n + 1]), (u32::MAX, u32::MAX));
        }
    }
}

#[test]
fn u64_transform_matches_generic_reference_across_modulus_ranges() {
    for q in [536813569u64, 562949953392641, 1152921504606830593] {
        let modulus = BarrettModulus::new(q);

        // N<16 forces scalar32/scalar64 even on hosts with AVX-512.
        for n in [8, 16, N] {
            let log_n = n.trailing_zeros();
            let table = U64NttTable::new(log_n, modulus).unwrap();
            let reference = UintNttTable::<u64>::new(log_n, modulus).unwrap();

            assert_transform_matches_reference(&table, &reference, &deterministic_u64_input(n, q));
        }
    }
}

#[test]
fn u64_transform_matches_generic_at_recursive_sizes() {
    // At 2048 AVX-512 uses its base case; 4096/8192 exercise one/two
    // recursion levels and subtree root offsets. Keep low-q DQ32 fallback,
    // IFMA52 and DQ64 modulus ranges; the middle range only needs depth two.
    for (q, lengths) in [
        (1_073_692_673u64, &[2048usize, 4096, 8192][..]),
        (1_125_899_906_826_241, &[8192][..]),
        (1_152_921_504_606_830_593, &[2048, 4096, 8192][..]),
    ] {
        let modulus = BarrettModulus::new(q);
        for &n in lengths {
            let table = U64NttTable::new(n.trailing_zeros(), modulus).unwrap();
            let reference = UintNttTable::<u64>::new(n.trailing_zeros(), modulus).unwrap();
            let mut input = deterministic_u64_input(n, q);
            // Include near-modulus values to stress the reduction paths too.
            for (i, value) in input.iter_mut().enumerate().step_by(3) {
                *value = q - 1 - i as u64;
            }
            assert_transform_matches_reference(&table, &reference, &input);
        }
    }
}

#[test]
fn u64_lazy_transforms_match_generic_reference_across_modulus_ranges() {
    for q in [536813569u64, 562949953392641, 1152921504606830593] {
        let modulus = BarrettModulus::new(q);
        let table = U64NttTable::new(LOG_N, modulus).unwrap();
        let reference = UintNttTable::<u64>::new(LOG_N, modulus).unwrap();

        let mut actual = vec![4 * q - 1; N];
        let mut expected = vec![q - 1; N];
        table.lazy_transform_slice(&mut actual);
        reference.transform_slice(&mut expected);
        assert!(
            actual.iter().all(|&value| value < 4 * q),
            "lazy forward output exceeded [0, 4q) for q={q}"
        );
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert_eq!(actual % q, expected, "lazy forward mismatch for q={q}");
        }

        let mut actual = vec![2 * q - 1; N];
        let mut expected = vec![q - 1; N];
        table.lazy_inverse_transform_slice(&mut actual);
        reference.inverse_transform_slice(&mut expected);
        assert!(
            actual.iter().all(|&value| value < 2 * q),
            "lazy inverse output exceeded [0, 2q) for q={q}"
        );
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert_eq!(actual % q, expected, "lazy inverse mismatch for q={q}");
        }
    }
}

#[test]
fn monomial_transform_matches_full_ntt() {
    let q32 = 268369921u32;
    let modulus32 = BarrettModulus::new(q32);
    assert_monomial_suite(&U32NttTable::new(LOG_N, modulus32).unwrap(), q32 / 3);
    assert_monomial_suite(
        &UintNttTable::<u32>::new(LOG_N, modulus32).unwrap(),
        q32 / 3,
    );

    let q64 = 562949953392641u64;
    let modulus64 = BarrettModulus::new(q64);
    assert_monomial_suite(&U64NttTable::new(LOG_N, modulus64).unwrap(), q64 / 3);
    assert_monomial_suite(
        &UintNttTable::<u64>::new(LOG_N, modulus64).unwrap(),
        q64 / 3,
    );
}
