use primus_modulus::BarrettModulus;
use primus_rns::{BaseConverter, RNSBase};

type Value = u64;
type Modulus = BarrettModulus<Value>;
type Base = RNSBase<Value, Modulus>;

fn base(moduli: &[Value]) -> Base {
    let moduli: Vec<_> = moduli.iter().copied().map(Modulus::new).collect();
    Base::new(&moduli).unwrap()
}

#[test]
fn fast_array_conversion_matches_scalar_conversion() {
    let input_base = base(&[17, 19, 23]);
    let output_base = base(&[29, 31]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let input = [
        0, 1, 16, 7, // mod 17
        0, 2, 18, 11, // mod 19
        0, 3, 22, 13, // mod 23
    ];
    let value_count = input.len() / input_base.moduli_count();
    let mut expected = vec![0; output_base.moduli_count() * value_count];

    for value_index in 0..value_count {
        let value_residues = [
            input[value_index],
            input[value_count + value_index],
            input[2 * value_count + value_index],
        ];
        let mut scalar_output = vec![0; output_base.moduli_count()];
        let mut scalar_scratch = vec![0; input_base.moduli_count()];
        converter.fast_convert(&value_residues, &mut scalar_output, &mut scalar_scratch);
        for (modulus_index, value) in scalar_output.into_iter().enumerate() {
            expected[modulus_index * value_count + value_index] = value;
        }
    }

    let mut output = vec![0; expected.len()];
    let required_scratch_len = converter.fast_convert_array_scratch_len(value_count);
    let mut scratch = vec![Value::MAX; required_scratch_len + 3];
    converter.fast_convert_array(&input, &mut output, value_count, &mut scratch);
    assert_eq!(output, expected);
    assert_eq!(&scratch[required_scratch_len..], &[Value::MAX; 3]);
}

#[test]
fn single_input_fast_and_exact_conversion_use_distinct_lifts() {
    let input_base = base(&[17]);
    let fast_output_base = base(&[13, 19]);
    let fast_converter = BaseConverter::new(&input_base, &fast_output_base);
    let input = [0, 1, 8, 9, 16];
    let mut fast_output = [Value::MAX; 10];
    let mut fast_scratch = [Value::MAX; 5];

    fast_converter.fast_convert_array(&input, &mut fast_output, input.len(), &mut fast_scratch);

    assert_eq!(fast_output, [0, 1, 8, 9, 3, 0, 1, 8, 9, 16]);
    assert_eq!(fast_scratch, [Value::MAX; 5]);

    let exact_output_base = base(&[13]);
    let exact_converter = BaseConverter::new(&input_base, &exact_output_base);
    let mut exact_output = [Value::MAX; 5];
    let mut context = exact_converter.exact_conversion_context(input.len());

    exact_converter.exact_convert_array(&input, &mut exact_output, input.len(), &mut context);

    assert_eq!(exact_output, [0, 1, 8, 5, 12]);
}

#[test]
fn exact_array_conversion_uses_centered_values_and_reuses_context() {
    let input_moduli = [17, 19, 23];
    let input_base = base(&input_moduli);
    let output_base = base(&[37]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let values = [0, 1, 2, 7, 16, 7_428];
    let input: Vec<_> = input_moduli
        .iter()
        .flat_map(|&modulus| values.iter().map(move |&value| value % modulus))
        .collect();
    let mut output = vec![Value::MAX; values.len()];
    let mut context = converter.exact_conversion_context(values.len());

    converter.exact_convert_array(&input, &mut output, values.len(), &mut context);
    assert_eq!(output, [0, 1, 2, 7, 16, 36]);

    output.fill(Value::MAX);
    converter.exact_convert_array(&input, &mut output, values.len(), &mut context);
    assert_eq!(output, [0, 1, 2, 7, 16, 36]);
}
