//! DCRT packing and construction contracts, using small component transforms
//! as the oracle for modulus order and inverse normalization.

use num_traits::{ConstOne, ConstZero};
use primus_integer::AsFrom;
use primus_modulus::BarrettModulus;
use primus_ntt::{
    DcrtTable, MonomialNttTable, NttError, U32DcrtTable, U32NttTable, U64NttTable, UintNttTable,
};
use primus_poly::PolyLength;
use primus_reduce::FieldContext;

// Distinct moduli make swapped limbs observable; deterministic nonconstant
// coefficients expose skipped blocks without relying on forward/inverse cancellation.
fn check_components<Table: MonomialNttTable>()
where
    BarrettModulus<Table::ValueT>: FieldContext<Table::ValueT>,
{
    let poly_length = PolyLength::new(32);
    let n = poly_length.get();
    let moduli = [257u32, 769].map(|q| BarrettModulus::new(Table::ValueT::as_from(q)));
    let table = DcrtTable::<Table>::new(poly_length, &moduli).unwrap();
    let components = moduli.map(|modulus| Table::new(poly_length, modulus).unwrap());
    // Convert lazy representatives by their modulus-major position only.
    let canonical = |values: &[Table::ValueT]| -> Vec<_> {
        values
            .iter()
            .enumerate()
            .map(|(i, &value)| value % moduli[i / n].value())
            .collect()
    };
    let input: Vec<_> = (0..table.rns_poly_len())
        .map(|i| Table::ValueT::as_from((i * i + 7 * i + 3) % [257, 769][i / n]))
        .collect();
    let mut expected = input.clone();
    for (values, component) in expected.chunks_exact_mut(n).zip(&components) {
        component.transform_slice(values);
    }

    let mut actual = input.clone();
    table.transform_slice(&mut actual);
    assert_eq!(actual, expected);
    table.inverse_transform_slice(&mut actual);
    assert_eq!(actual, input);

    actual.copy_from_slice(&input);
    table.lazy_transform_slice(&mut actual);
    assert_eq!(canonical(&actual), expected);
    // Feed the independently transformed canonical oracle to the lazy inverse.
    actual.copy_from_slice(&expected);
    table.lazy_inverse_transform_slice(&mut actual);
    assert_eq!(canonical(&actual), input);

    // Direct monomials must overwrite every limb, including zero coefficients
    // and the X^N = -1 sign boundary. Full transforms supply the oracle.
    for degree in [0, 7, n, n + 7, 2 * n] {
        for coefficient in [0u32, 1, 13] {
            let coefficient = Table::ValueT::as_from(coefficient);
            expected.fill(Table::ValueT::ZERO);
            for ((values, component), modulus) in
                expected.chunks_exact_mut(n).zip(&components).zip(moduli)
            {
                values[degree % n] = if degree % (2 * n) < n || coefficient == Table::ValueT::ZERO {
                    coefficient
                } else {
                    modulus.value() - coefficient
                };
                component.transform_slice(values);
            }
            actual.fill(Table::ValueT::ONE);
            table.transform_monomial(coefficient, degree, &mut actual);
            assert_eq!(actual, expected);
            if coefficient == Table::ValueT::ONE {
                actual.fill(Table::ValueT::ONE);
                table.transform_coeff_one_monomial(degree, &mut actual);
                assert_eq!(actual, expected);
                table.transform_coeff_minus_one_monomial(degree, &mut actual);
                for (index, (&value, &expected)) in actual.iter().zip(&expected).enumerate() {
                    assert_eq!(
                        value,
                        if expected == Table::ValueT::ZERO {
                            expected
                        } else {
                            moduli[index / n].value() - expected
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn dcrt_transforms_preserve_component_order_and_normalization() {
    check_components::<UintNttTable<u32>>();
    check_components::<U32NttTable>();
    check_components::<UintNttTable<u64>>();
    check_components::<U64NttTable>();
}

#[test]
fn dcrt_rejects_empty_basis() {
    assert!(matches!(
        U32DcrtTable::new(PolyLength::new(32), &[] as &[BarrettModulus<u32>]),
        Err(NttError::EmptyModuli)
    ));
}
