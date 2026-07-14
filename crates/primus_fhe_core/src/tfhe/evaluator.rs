/// An error produced while constructing or running a TFHE evaluator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheEvaluationError {
    /// The server key was generated for a different parameter layout.
    #[error("TFHE server key is incompatible with the evaluation context")]
    IncompatibleServerKey,

    /// The input ciphertext has an unexpected LWE dimension.
    #[error("input LWE dimension mismatch: expected {expected}, got {actual}")]
    InputDimensionMismatch {
        /// Dimension required by the evaluator.
        expected: usize,
        /// Dimension carried by the input ciphertext.
        actual: usize,
    },

    /// The output ciphertext has an unexpected LWE dimension.
    #[error("output LWE dimension mismatch: expected {expected}, got {actual}")]
    OutputDimensionMismatch {
        /// Dimension required by the evaluator.
        expected: usize,
        /// Dimension carried by the output ciphertext.
        actual: usize,
    },

    /// The lookup-table accumulator has an unexpected coefficient count.
    #[error("lookup-table length mismatch: expected {expected}, got {actual}")]
    LookupTableLengthMismatch {
        /// Required GLWE coefficient count.
        expected: usize,
        /// Supplied GLWE coefficient count.
        actual: usize,
    },
}
