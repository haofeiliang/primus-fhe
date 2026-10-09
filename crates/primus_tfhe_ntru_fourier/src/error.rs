pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to prepare NTRU operation state or bind it to a Fourier table.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError {
    /// Preparing the selected operation or pairing independent operation state failed.
    #[error(transparent)]
    Parameters(#[from] TfheParameterError),

    /// The Fourier table uses another polynomial length.
    #[error("Fourier polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Required NTRU polynomial length.
        expected: usize,
        /// Fourier table polynomial length.
        actual: usize,
    },
}
