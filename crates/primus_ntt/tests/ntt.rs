use core::fmt::Debug;

use num_traits::{ConstOne, ConstZero};
use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::{MonomialNttTable, NttTable, U32NttTable, U64NttTable, UintNttTable};

const N: usize = 256;
const LOG_N: u32 = N.trailing_zeros();

fn deterministic_u32_input(modulus: u32) -> Vec<u32> {
    (0..N)
        .map(|i| {
            let i = i as u32;
            (17 * i * i + 31 * i + 7) % modulus
        })
        .collect()
}

fn deterministic_u64_input(modulus: u64) -> Vec<u64> {
    (0..N)
        .map(|i| {
            let i = i as u64;
            (17 * i * i + 31 * i + 7) % modulus
        })
        .collect()
}

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

#[test]
fn u32_transform_matches_generic_reference() {
    let q = 268369921u32;
    let modulus = BarrettModulus::new(q);
    let table = U32NttTable::new(LOG_N, modulus).unwrap();
    let reference = UintNttTable::<u32>::new(LOG_N, modulus).unwrap();

    assert_transform_matches_reference(&table, &reference, &deterministic_u32_input(q));
}

#[test]
fn u64_transform_matches_generic_reference_across_modulus_ranges() {
    for q in [536813569u64, 562949953392641, 1152921504606830593] {
        let modulus = BarrettModulus::new(q);
        let table = U64NttTable::new(LOG_N, modulus).unwrap();
        let reference = UintNttTable::<u64>::new(LOG_N, modulus).unwrap();

        assert_transform_matches_reference(&table, &reference, &deterministic_u64_input(q));
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
