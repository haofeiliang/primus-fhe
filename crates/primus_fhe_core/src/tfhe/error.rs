//! Errors shared by TFHE execution backends.

/// An error produced while constructing a TFHE evaluator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheEvaluationError {
    /// The server key was generated for a different parameter layout.
    #[error("TFHE server key is incompatible with the evaluation context")]
    IncompatibleServerKey,
}
