pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    NtruClientError as TfheClientError, NtruParameterError as TfheParameterError,
};

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

/// An error produced while generating Fourier NTRU TFHE keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// A coefficient NTRU secret has no stable Fourier inverse.
    #[error(transparent)]
    Ntru(#[from] primus_ntru::NtruError),
    /// A supplied client key does not match the parameters.
    #[error(transparent)]
    Client(#[from] primus_tfhe_ntru::NtruKeyError),
}
