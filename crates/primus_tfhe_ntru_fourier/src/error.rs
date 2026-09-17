pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{TfheClientError, TfheKeyError, TfheParameterError};

/// An incompatibility between NTRU TFHE parameters and a Fourier table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
