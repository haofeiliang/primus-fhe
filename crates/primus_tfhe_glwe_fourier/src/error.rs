//! Errors produced by the Fourier TFHE backend.

pub use primus_fhe_core::{
    BooleanError, LookupTableError, TfheClientError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};

/// An incompatibility between TFHE parameters and a Fourier table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheContextError {
    /// The Fourier table was built for a different polynomial length.
    #[error("FFT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the GLWE parameters.
        expected: usize,
        /// Polynomial length supported by the Fourier table.
        actual: usize,
    },
}
