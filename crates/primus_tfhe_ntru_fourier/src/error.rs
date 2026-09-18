pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    CircuitBootstrapParameterError, KeyGenerationError, TfheClientError, TfheKeyError,
    TfheParameterError,
};

/// Failure to construct a Fourier table or bind it to NTRU TFHE parameters.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError {
    /// The selected transform table could not be constructed.
    #[error("failed to construct transform table: {0}")]
    TransformTable(#[from] primus_fft::FftError),
    /// The Fourier table uses another polynomial length.
    #[error("Fourier polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Required NTRU polynomial length.
        expected: usize,
        /// Fourier table polynomial length.
        actual: usize,
    },
}
