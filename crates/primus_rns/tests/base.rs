use primus_factor::ShoupFactor;
use primus_integer::BigUint;
use primus_modulus::BarrettModulus;
use primus_reduce::prelude::*;
use primus_rns::{RNSBase, RNSError, ResidueFactors, Residues};

type Value = u64;
type Modulus = BarrettModulus<Value>;
type Base = RNSBase<Value, Modulus>;

fn base(moduli: &[Value]) -> Base {
    let moduli: Vec<_> = moduli.iter().copied().map(Modulus::new).collect();
    Base::new(&moduli).unwrap()
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

#[test]
fn scalar_crt_matches_known_representatives() {
    let singleton = base(&[3]);
    assert_eq!(singleton.moduli_product().digits(), &[3]);
    let value = singleton.compose(&Residues([2]));
    assert_eq!(value.digits(), &[2]);
    assert_eq!(singleton.decompose(value.view()).as_ref(), [2]);

    let base = base(&[3, 5, 7]);
    assert_eq!(base.moduli_product().digits(), &[105]);
    let value = base.compose(&Residues([2, 4, 6]));
    assert_eq!(value.digits(), &[104]);
    assert_eq!(base.decompose(value.view()).as_ref(), [2, 4, 6]);
    let mut storage = [Value::MAX; 3];
    let mut output = Residues::new(storage.as_mut_slice());
    base.decompose_to(value.view(), &mut output);
    let mut reconstructed = BigUint(vec![Value::MAX; base.big_uint_value_len()]);
    base.compose_to(&output.view(), &mut reconstructed.view_mut());
    assert_eq!(reconstructed, value);
    assert_eq!(storage, [2, 4, 6]);
}

#[test]
fn compose_and_decompose_preserve_the_modulus_major_layout() {
    let base = base(&[1_125_899_906_826_241, 1_125_899_906_629_633]);
    let residues = [
        [0, 0],
        [1, 2],
        [97, 131],
        [base.moduli()[0].value() - 1, base.moduli()[1].value() - 2],
    ];
    let expected = [
        residues[0][0],
        residues[1][0],
        residues[2][0],
        residues[3][0],
        residues[0][1],
        residues[1][1],
        residues[2][1],
        residues[3][1],
    ];
    let value_len = base.big_uint_value_len();
    let mut values = vec![0; residues.len() * value_len];
    for (index, value_residues) in residues.iter().enumerate() {
        values[index * value_len..(index + 1) * value_len]
            .copy_from_slice(base.compose(&Residues(value_residues)).digits());
    }

    let mut decomposed = vec![Value::MAX; expected.len()];
    base.decompose_big_uint_values_to(&values, &mut decomposed, residues.len());
    assert_eq!(decomposed, expected);

    let mut recomposed = vec![Value::MAX; values.len()];
    let mut scratch = vec![0; base.moduli_count()];
    base.compose_big_uint_values_to(&expected, &mut recomposed, residues.len(), &mut scratch);
    assert_eq!(recomposed, values);
}

#[test]
fn wrapping_and_scaled_decomposition_follow_the_centered_rule() {
    let base = base(&[97, 101, 103]);
    let factor_values = [3, 5, 7];
    let factors = ResidueFactors(
        factor_values
            .iter()
            .zip(base.moduli())
            .map(|(&factor, modulus)| ShoupFactor::new(factor, modulus.value()))
            .collect::<Vec<_>>(),
    );

    const BINARY_VALUES: &[Value] = &[0, 1];
    const ODD_MODULUS_VALUES: &[Value] = &[0, 1, 3, 4, 6];
    let cases: [(Value, &[Value]); 2] = [(2, BINARY_VALUES), (7, ODD_MODULUS_VALUES)];
    for (small_modulus, values) in cases {
        let centered = |value: Value, modulus: Value| {
            if small_modulus == 2 || value < small_modulus.div_ceil(2) {
                value
            } else {
                modulus - small_modulus + value
            }
        };

        let mut decomposed = vec![Value::MAX; base.moduli_count() * values.len()];
        base.wrapping_decompose_small_values_to(values, &mut decomposed, small_modulus);
        let mut accumulated = vec![11; decomposed.len()];
        base.add_wrapping_decompose_small_values_scaled_assign(
            values,
            &mut accumulated,
            small_modulus,
            &factors,
        );

        for (modulus_index, modulus) in base.moduli().iter().enumerate() {
            for (value_index, &value) in values.iter().enumerate() {
                let expected = centered(value, modulus.value());
                assert_eq!(
                    decomposed[modulus_index * values.len() + value_index],
                    expected
                );
                let product = modulus.reduce_mul(factor_values[modulus_index], expected);
                assert_eq!(
                    accumulated[modulus_index * values.len() + value_index],
                    modulus.reduce_add(11, product)
                );
            }
        }
    }
}

#[test]
fn extending_a_base_matches_fresh_construction() {
    let assert_equivalent = |extended: &Base, direct: &Base, residues: &[Value]| {
        assert_eq!(extended.moduli_product(), direct.moduli_product());
        assert_eq!(
            extended.compose(&Residues(residues)),
            direct.compose(&Residues(residues))
        );
    };

    let q = base(&[17]);
    let extended = q.extend(Modulus::new(19)).unwrap();
    let direct = base(&[17, 19]);
    assert_equivalent(&extended, &direct, &[1, 2]);

    let q = base(&[1_125_899_906_826_241, 1_125_899_906_629_633]);
    let p = base(&[1_125_899_906_031_617, 1_125_899_906_588_673]);

    let extended = q.extend(p.moduli()[0]).unwrap();
    let direct = base(&[
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
    ]);
    assert_equivalent(&extended, &direct, &[1, 2, 3]);

    let extended = q.extend_with(&p).unwrap();
    let direct = base(&[
        1_125_899_906_826_241,
        1_125_899_906_629_633,
        1_125_899_906_031_617,
        1_125_899_906_588_673,
    ]);
    assert_equivalent(&extended, &direct, &[1, 2, 3, 4]);
}
