//! Boolean-owned constructor and dimension checks, without cryptographic setup.

use primus_encoding::RoundedCodec;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_tfhe::{
    BooleanEvaluator, BooleanGate, LookupTable, LweCiphertext, ProgrammableBootstrap,
    TfheEvaluationError,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

struct UnusedBootstrap;

impl ProgrammableBootstrap<u32> for UnusedBootstrap {
    fn apply_lookup_table_to(
        &mut self,
        _: &LweCiphertext<u32>,
        _: &LookupTable<u32>,
        _: &mut LweCiphertext<u32>,
    ) {
        panic!("constructor must not invoke PBS");
    }
}

/// Rejects invalid input/internal encodings before any backend operation.
#[test]
fn boolean_constructor_checks_both_encoding_scales() {
    // An ordinary t=4 codec can be valid even when q cannot represent t=8.
    for (t, input_q, accumulator_q) in [(8, 257, 257), (4, 7, 257), (4, 257, 7)] {
        let codec = RoundedCodec::new(t, BarrettModulus::new(input_q));
        assert_eq!(
            BooleanEvaluator::try_new(
                3,
                16,
                &codec,
                BarrettModulus::new(accumulator_q),
                UnusedBootstrap
            )
            .err(),
            Some(TfheEvaluationError::InvalidBooleanEncoding),
        );
    }
    let codec = RoundedCodec::new(4, NativeModulus::new());
    assert!(matches!(
        BooleanEvaluator::try_new(3, 1, &codec, NativeModulus::new(), UnusedBootstrap),
        Err(TfheEvaluationError::LookupTable(_))
    ));
}

/// Allows MUX's first PBS to finish before its later else-input check.
/// It deliberately does not validate dimensions or panic: rejection must come
/// from BooleanEvaluator, not from a failing test double. No phase is decrypted.
#[derive(Default)]
struct RecordingBootstrap {
    calls: usize,
}

impl ProgrammableBootstrap<u32> for RecordingBootstrap {
    fn apply_lookup_table_to(
        &mut self,
        _: &LweCiphertext<u32>,
        _: &LookupTable<u32>,
        output: &mut LweCiphertext<u32>,
    ) {
        self.calls += 1;
        output.as_mut().fill(0);
    }
}

/// Checks both rejection and the caller-visible output sentinel.
fn rejects_without_writing(
    initial: &LweCiphertext<u32>,
    operation: impl FnOnce(&mut LweCiphertext<u32>),
) {
    let mut output = initial.clone();
    assert!(catch_unwind(AssertUnwindSafe(|| operation(&mut output))).is_err());
    assert_eq!(&output, initial);
}

/// Covers short/long inputs and NOT outputs at the layer owning their checks.
/// PBS-owned output dimensions are tested with the real backend evaluators.
#[test]
fn boolean_dimension_checks_preserve_output_at_each_stage() {
    const DIMENSION: usize = 3;
    let modulus = NativeModulus::new();
    let codec = RoundedCodec::new(4, modulus);
    let mut evaluator = BooleanEvaluator::try_new(
        DIMENSION,
        16,
        &codec,
        modulus,
        RecordingBootstrap::default(),
    )
    .unwrap();
    let input = LweCiphertext::new(vec![7; DIMENSION + 1]);

    for dimension in [DIMENSION - 1, DIMENSION + 1] {
        let wrong = LweCiphertext::new(vec![11; dimension + 1]);
        evaluator.bootstrapper_mut().calls = 0;

        // Binary inputs and MUX's condition/then inputs are checked before PBS.
        for (lhs, rhs) in [(&wrong, &input), (&input, &wrong)] {
            rejects_without_writing(&input, |output| {
                evaluator.evaluate_binary_to(BooleanGate::And, lhs, rhs, output);
            });
            rejects_without_writing(&input, |output| {
                evaluator.mux_to(lhs, rhs, &input, output);
            });
        }
        assert_eq!(evaluator.bootstrapper().calls, 0);

        // MUX may have computed its first branch in scratch when it rejects else.
        // Allow an earlier check too; the public output must remain untouched.
        rejects_without_writing(&input, |output| {
            evaluator.mux_to(&input, &input, &wrong, output);
        });
        let calls = evaluator.bootstrapper().calls;
        assert!(
            calls <= 1,
            "invalid else input must not reach the second PBS"
        );

        // NOT has its own input/output checks and never invokes PBS.
        for (input, initial_output) in [(&wrong, &input), (&input, &wrong)] {
            rejects_without_writing(initial_output, |output| evaluator.not_to(input, output));
        }
        assert_eq!(evaluator.bootstrapper().calls, calls);
    }
}
