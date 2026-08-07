use primus_integer::FheUint;

pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_ntru::{
    NtruClientError as TfheClientError, NtruParameterError as TfheParameterError,
};

/// An incompatibility between NTRU TFHE parameters and an NTT table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheContextError<T: FheUint> {
    /// The NTT table uses another polynomial length.
    #[error("NTT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Required NTRU polynomial length.
        expected: usize,
        /// NTT table polynomial length.
        actual: usize,
    },
    /// The NTT table uses another coefficient modulus.
    #[error("NTT modulus mismatch: expected {expected:?}, got {actual:?}")]
    ModulusMismatch {
        /// Required NTRU modulus.
        expected: T,
        /// NTT table modulus.
        actual: T,
    },
}

/// An error produced while generating NTRU TFHE keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// A coefficient NTRU secret cannot be used by the selected NTT ring.
    #[error(transparent)]
    Ntru(#[from] primus_ntru::NtruError),
    /// A supplied client key does not match the parameters.
    #[error(transparent)]
    Client(#[from] primus_tfhe_ntru::NtruKeyError),
}
