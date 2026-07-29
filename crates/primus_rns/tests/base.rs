use primus_factor::{FactorBase, ShoupFactor};
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;
use primus_rns::{RNSBase, RNSError};

type Value = u64;
type Modulus = BarrettModulus<Value>;
type Base = RNSBase<Value, Modulus>;

fn base(moduli: &[Value]) -> Base {
    let moduli: Vec<_> = moduli.iter().copied().map(Modulus::new).collect();
    Base::new(&moduli).unwrap()
}

fn pack_modulus_major(residues: &[Vec<Value>], moduli_count: usize) -> Vec<Value> {
    let value_count = residues.len();
    let mut packed = vec![0; moduli_count * value_count];
    for (value_index, value_residues) in residues.iter().enumerate() {
        for (modulus_index, &residue) in value_residues.iter().enumerate() {
            packed[modulus_index * value_count + value_index] = residue;
        }
    }
    packed
}

#[test]
fn construction_rejects_invalid_bases() {
    assert!(matches!(Base::new(&[]), Err(RNSError::EmptyBase)));

    let non_coprime = [21, 35].map(Modulus::new);
    assert!(matches!(
        Base::new(&non_coprime),
        Err(RNSError::CoPrimeError)
    ));
}

/// Verifies the singleton representation and independently checks the
/// punctured products constructed for a multi-modulus base.
#[test]
fn construction_computes_punctured_products() {
    let singleton = base(&[3]);
    assert_eq!(singleton.moduli_product().digits(), &[3]);
    assert_eq!(singleton.punctured_product(), &[1]);

    let base = base(&[3, 5, 7]);
    assert_eq!(base.moduli_product().digits(), &[105]);
    assert_eq!(base.punctured_product(), &[35, 21, 15]);
}

#[test]
fn compose_and_decompose_preserve_the_modulus_major_layout() {
    let base = base(&[1_125_899_906_826_241, 1_125_899_906_629_633]);
    let residues = vec![
        vec![0, 0],
        vec![1, 2],
        vec![97, 131],
        vec![base.moduli()[0].value() - 1, base.moduli()[1].value() - 2],
    ];
    let expected = pack_modulus_major(&residues, base.moduli_count());
    let value_len = base.big_uint_value_len();
    let mut values = vec![0; residues.len() * value_len];
    for (index, value_residues) in residues.iter().enumerate() {
        values[index * value_len..(index + 1) * value_len]
            .copy_from_slice(base.compose(value_residues).digits());
    }

    let mut decomposed = vec![Value::MAX; expected.len()];
    base.decompose_big_uint_values_to(&values, &mut decomposed, residues.len());
    assert_eq!(decomposed, expected);

    let mut recomposed = vec![Value::MAX; values.len()];
    let mut scratch = vec![0; base.moduli_count()];
    base.compose_multiple_values_to(&expected, &mut recomposed, residues.len(), &mut scratch);
    assert_eq!(recomposed, values);

    let scalar = base.compose(&residues[2]);
    assert_eq!(base.decompose(scalar.view()), residues[2]);
}

#[test]
fn wrapping_and_scaled_decomposition_follow_the_centered_rule() {
    let base = base(&[97, 101, 103]);
    let small_modulus: Value = 7;
    let values = [0, 1, 3, 4, 6];
    let expected_centered = |value: Value, modulus: Value| {
        if value < small_modulus.div_ceil(2) {
            value
        } else {
            modulus - small_modulus + value
        }
    };

    let mut decomposed = vec![Value::MAX; base.moduli_count() * values.len()];
    base.wrapping_decompose_small_values_to(&values, &mut decomposed, values.len(), small_modulus);

    for (modulus_index, modulus) in base.moduli().iter().enumerate() {
        for (value_index, &value) in values.iter().enumerate() {
            assert_eq!(
                decomposed[modulus_index * values.len() + value_index],
                expected_centered(value, modulus.value())
            );
        }
    }

    let factor_values = [3, 5, 7];
    let factors: Vec<_> = factor_values
        .iter()
        .zip(base.moduli())
        .map(|(&factor, modulus)| ShoupFactor::new(factor, modulus.value()))
        .collect();
    let mut accumulated = vec![11; decomposed.len()];
    base.add_wrapping_decompose_small_values_scaled(
        &values,
        &mut accumulated,
        values.len(),
        small_modulus,
        &factors,
    );

    for (modulus_index, modulus) in base.moduli().iter().enumerate() {
        for (value_index, &value) in values.iter().enumerate() {
            let centered = expected_centered(value, modulus.value());
            let product = modulus.reduce_mul(factor_values[modulus_index], centered);
            assert_eq!(
                accumulated[modulus_index * values.len() + value_index],
                modulus.reduce_add(11, product)
            );
        }
    }
}

#[test]
fn extending_a_base_matches_fresh_construction() {
    let q = base(&[1_125_899_906_826_241, 1_125_899_906_629_633]);
    let p = base(&[1_125_899_906_031_617, 1_125_899_906_588_673]);
    let extended = q.extend_with(&p).unwrap();
    let direct = base(&[
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
        1_125_899_906_588_673,
    ]);

    assert_eq!(extended.moduli_product(), direct.moduli_product());
    assert_eq!(extended.punctured_product(), direct.punctured_product());
    assert!(
        extended
            .inv_punctured_product_mod_modulus()
            .iter()
            .map(|factor| factor.value())
            .eq(direct
                .inv_punctured_product_mod_modulus()
                .iter()
                .map(|factor| factor.value()))
    );
}
