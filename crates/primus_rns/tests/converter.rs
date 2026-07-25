use primus_modulus::BarrettModulus;
use primus_rns::{BaseConverter, RNSBase};

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
fn fast_array_conversion_matches_scalar_conversion() {
    let input_base = base(&[17, 19, 23]);
    let output_base = base(&[29, 31]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let residues = vec![
        vec![0, 0, 0],
        vec![1, 2, 3],
        vec![16, 18, 22],
        vec![7, 11, 13],
    ];
    let value_count = residues.len();
    let input = pack_modulus_major(&residues, input_base.moduli_count());
    let mut expected = vec![0; output_base.moduli_count() * value_count];

    for (value_index, value_residues) in residues.iter().enumerate() {
        let mut scalar_output = vec![0; output_base.moduli_count()];
        let mut scalar_scratch = vec![0; input_base.moduli_count()];
        converter.fast_convert(value_residues, &mut scalar_output, &mut scalar_scratch);
        for (modulus_index, value) in scalar_output.into_iter().enumerate() {
            expected[modulus_index * value_count + value_index] = value;
        }
    }

    let mut output = vec![0; expected.len()];
    let mut scratch = vec![0; input_base.moduli_count() * value_count];
    converter.fast_convert_array(&input, &mut output, value_count, &mut scratch);
    assert_eq!(output, expected);
}

#[test]
fn exact_array_conversion_matches_canonical_values() {
    let input_base = base(&[17, 19, 23]);
    let output_base = base(&[37]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let values = [0, 1, 2, 7, 16];
    let residues: Vec<_> = values
        .iter()
        .map(|&value| vec![value; input_base.moduli_count()])
        .collect();
    let input = pack_modulus_major(&residues, input_base.moduli_count());
    let mut output = vec![Value::MAX; values.len()];

    converter.exact_convert_array(&input, &mut output, values.len());
    assert_eq!(output, values);
}
