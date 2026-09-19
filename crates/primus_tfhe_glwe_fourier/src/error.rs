//! Errors produced by the Fourier TFHE backend.

pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_glwe::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Failure to construct a Fourier table or bind it to TFHE parameters.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError {
    /// The selected transform table could not be constructed.
    #[error("failed to construct transform table: {0}")]
    TransformTable(#[from] primus_fft::FftError),
    /// The Fourier table was built for a different polynomial length.
    #[error("FFT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the GLWE parameters.
        expected: usize,
        /// Polynomial length supported by the Fourier table.
        actual: usize,
    },
}
