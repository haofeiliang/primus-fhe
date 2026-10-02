pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to bind a Fourier table to NTRU TFHE parameters.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError {
    /// The Fourier table uses another polynomial length.
    #[error("Fourier polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Required NTRU polynomial length.
        expected: usize,
        /// Fourier table polynomial length.
        actual: usize,
    },
}
