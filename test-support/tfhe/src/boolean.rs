//! Common Boolean truth tables and gate chains for real backend evaluators.
//! Constructor and Boolean-owned dimension checks live in primus_tfhe's tests;
//! each backend checks its own PBS output boundary in its integration tests.

use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{BooleanEvaluator, BooleanGate, LweCiphertext, ProgrammableBootstrap};

/// Checks all binary-gate, NOT and MUX truth tables against ordinary booleans,
/// then feeds outputs through NAND -> NOT -> MUX -> XOR to check reusable encoding.
///
/// `inputs` encrypt `[false, true]` under the evaluator's key. `output` and
/// `current` have the same dimension and are overwritten. Key generation and
/// decryption stay with the backend-specific caller.
pub fn check_truth_tables_and_chain<T, M, E>(
    evaluator: &mut BooleanEvaluator<T, M, E>,
    inputs: &[LweCiphertext<T>; 2],
    output: &mut LweCiphertext<T>,
    current: &mut LweCiphertext<T>,
    decrypt: impl Fn(&LweCiphertext<T>) -> bool,
) where
    T: FheUint,
    M: RingContext<T>,
    E: ProgrammableBootstrap<T>,
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
