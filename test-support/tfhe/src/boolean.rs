//! Common Boolean truth tables, gate chains and dimension checks.

use primus_reduce::RingContext;
use primus_tfhe::{BooleanEvaluator, BooleanGate, LweCiphertext, ProgrammableBootstrap};
use std::panic::{AssertUnwindSafe, catch_unwind};

// All four backends use this oracle; key generation and client bindings stay local.
pub fn check_truth_tables_and_chain<M, E>(
    evaluator: &mut BooleanEvaluator<u32, M, E>,
    inputs: &[LweCiphertext<u32>; 2],
    output: &mut LweCiphertext<u32>,
    current: &mut LweCiphertext<u32>,
    decrypt: impl Fn(&LweCiphertext<u32>) -> bool,
) where
    M: RingContext<u32>,
    E: ProgrammableBootstrap<u32>,
{
    for lhs in [false, true] {
        for rhs in [false, true] {
            for (gate, expected) in [
                (BooleanGate::And, lhs & rhs),
                (BooleanGate::Nand, !(lhs & rhs)),
                (BooleanGate::Or, lhs | rhs),
                (BooleanGate::Nor, !(lhs | rhs)),
                (BooleanGate::Xor, lhs ^ rhs),
                (BooleanGate::Xnor, !(lhs ^ rhs)),
            ] {
                evaluator.evaluate_binary_to(
                    gate,
                    &inputs[lhs as usize],
                    &inputs[rhs as usize],
                    output,
                );
                assert_eq!(decrypt(output), expected, "{gate:?}({lhs}, {rhs})");
            }
        }
    }
    for value in [false, true] {
        evaluator.not_to(&inputs[value as usize], output);
        assert_eq!(decrypt(output), !value, "NOT({value})");
    }
    for condition in [false, true] {
        for then_value in [false, true] {
            for else_value in [false, true] {
                evaluator.mux_to(
                    &inputs[condition as usize],
                    &inputs[then_value as usize],
                    &inputs[else_value as usize],
                    output,
                );
                assert_eq!(
                    decrypt(output),
                    if condition { then_value } else { else_value },
                    "MUX({condition}, {then_value}, {else_value})"
                );
            }
        }
    }

    // Reconsume each operation's output: NAND -> NOT -> MUX -> XOR, swapping
    // two buffers. MUX's sum must restore the same encoding as a single PBS.
    evaluator.evaluate_binary_to(BooleanGate::Nand, &inputs[0], &inputs[1], current);
    assert!(decrypt(current));
    evaluator.not_to(current, output);
    assert!(!decrypt(output));
    core::mem::swap(current, output);
    evaluator.mux_to(current, &inputs[0], &inputs[1], output);
    assert!(decrypt(output));
    core::mem::swap(current, output);
    evaluator.evaluate_binary_to(BooleanGate::Xor, current, &inputs[1], output);
    assert!(!decrypt(output));
}

pub fn check_dimension_errors<M, E>(
    evaluator: &mut BooleanEvaluator<u32, M, E>,
    input: &LweCiphertext<u32>,
) where
    M: RingContext<u32>,
    E: ProgrammableBootstrap<u32>,
{
    fn rejects_without_writing(
        initial: &LweCiphertext<u32>,
        operation: impl FnOnce(&mut LweCiphertext<u32>),
    ) {
        let mut output = initial.clone();
        assert!(catch_unwind(AssertUnwindSafe(|| operation(&mut output))).is_err());
        assert_eq!(&output, initial);
    }

    let wrong = LweCiphertext::new(vec![1; input.dimension()]);
    // Binary preprocessing checks both inputs; the PBS backend checks output.
    for (lhs, rhs, output) in [
        (&wrong, input, input),
        (input, &wrong, input),
        (input, input, &wrong),
    ] {
        rejects_without_writing(output, |output| {
            evaluator.evaluate_binary_to(BooleanGate::And, lhs, rhs, output);
        });
    }
    // MUX has an additional else input; NOT bypasses the PBS boundary entirely.
    rejects_without_writing(input, |output| {
        evaluator.mux_to(input, input, &wrong, output);
    });
    for (input, output) in [(&wrong, input), (input, &wrong)] {
        rejects_without_writing(output, |output| evaluator.not_to(input, output));
    }
}
