use primus_modulus::BarrettModulus;
use primus_rns::Residues;
use primus_rns::{BaseConverter, RNSBase};

type Value = u64;
type Modulus = BarrettModulus<Value>;
type Base = RNSBase<Value, Modulus>;

fn base(moduli: &[Value]) -> Base {
    let moduli: Vec<_> = moduli.iter().copied().map(Modulus::new).collect();
    Base::new(&moduli).unwrap()
}

#[test]
fn fast_conversion_matches_independent_crt_sum() {
    let source_moduli = [17, 19, 23];
    let input_base = base(&source_moduli);
    // Adjusted source residues can exceed both destination moduli.
    let output_base = base(&[5, 7]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let input = [
        0, 1, 16, 7, // mod 17
        0, 2, 18, 11, // mod 19
        0, 3, 22, 13, // mod 23
    ];
    let value_count = input.len() / input_base.moduli_count();
    // An independent small-integer CRT sum: Q fits in u64, and inverses are
    // found by enumeration rather than using the converter's prepared factors.
    let q: u64 = source_moduli.iter().product();
    let lifts: Vec<u64> = (0..value_count)
        .map(|value_index| {
            source_moduli
                .iter()
                .enumerate()
                .map(|(i, &qi)| {
                    let punctured = q / qi;
                    let inverse = (1..qi)
                        .find(|&candidate| candidate * punctured % qi == 1)
                        .unwrap();
                    let adjusted = input[i * value_count + value_index] * inverse % qi;
                    adjusted * punctured
                })
                .sum()
        })
        .collect();
    let expected: Vec<_> = [5, 7]
        .iter()
        .flat_map(|&p| lifts.iter().map(move |&lift| lift % p))
        .collect();

    for value_index in 0..value_count {
        let value_residues = [
            input[value_index],
            input[value_count + value_index],
            input[2 * value_count + value_index],
        ];
        let mut scalar_output = vec![0; output_base.moduli_count()];
        let mut scalar_scratch = vec![0; input_base.moduli_count()];
        converter.fast_convert(
            &Residues(value_residues.as_slice()),
            &mut Residues(scalar_output.as_mut_slice()),
            &mut scalar_scratch,
        );
        for (modulus_index, value) in scalar_output.into_iter().enumerate() {
            assert_eq!(value, expected[modulus_index * value_count + value_index]);
        }
    }

    let mut output = vec![0; expected.len()];
    let required_scratch_len = converter.fast_convert_array_scratch_len(value_count);
    let mut scratch = vec![Value::MAX; required_scratch_len + 3];
    converter.fast_convert_array(&input, &mut output, value_count, &mut scratch);
    assert_eq!(output, expected);
    let paired: Vec<_> = converter
        .fast_convert_array_to_pair_iter(&input, value_count, &mut scratch)
        .collect();
    let expected_pairs: Vec<_> = lifts.iter().map(|&lift| (lift % 5, lift % 7)).collect();
    assert_eq!(paired, expected_pairs);
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
    let mut workspace = exact_converter.exact_conversion_workspace(input.len());

    exact_converter.exact_convert_array(&input, &mut exact_output, input.len(), &mut workspace);

    assert_eq!(exact_output, [0, 1, 8, 5, 12]);
}

#[test]
fn exact_array_conversion_uses_centered_values_and_reuses_workspace() {
    // 7428 = 17*19*23 - 1 represents -1, hence 4 modulo the destination 5.
    // Each source modulus exceeds the destination in this corrected path too.
    let input_moduli = [17, 19, 23];
    let input_base = base(&input_moduli);
    let output_base = base(&[5]);
    let converter = BaseConverter::new(&input_base, &output_base);
    let values = [0, 1, 2, 7, 16, 7_428];
    let input: Vec<_> = input_moduli
        .iter()
        .flat_map(|&modulus| values.iter().map(move |&value| value % modulus))
        .collect();
    let mut output = vec![Value::MAX; values.len()];
    let mut workspace = converter.exact_conversion_workspace(values.len());

    converter.exact_convert_array(&input, &mut output, values.len(), &mut workspace);
    assert_eq!(output, [0, 1, 2, 2, 1, 4]);

    output.fill(Value::MAX);
    converter.exact_convert_array(&input, &mut output, values.len(), &mut workspace);
    assert_eq!(output, [0, 1, 2, 2, 1, 4]);
}
