//! Errors produced by the NTT TFHE backend.

use primus_integer::FheUint;

pub use primus_fhe_core::{
    BooleanError, LookupTableError, TfheClientError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};

/// An incompatibility between TFHE parameters and an NTT table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheContextError<T: FheUint> {
    /// The NTT table was built for a different polynomial length.
    #[error("NTT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the GLWE parameters.
        expected: usize,
        /// Polynomial length supported by the NTT table.
        actual: usize,
    },

    /// The NTT table was built for a different coefficient modulus.
    #[error("NTT modulus mismatch: expected {expected:?}, got {actual:?}")]
    ModulusMismatch {
        /// Coefficient modulus required by the GLWE parameters.
        expected: T,
        /// Coefficient modulus supported by the NTT table.
        actual: T,
    },

    /// GLWE key switching followed by compact extraction requires the
    /// small-LWE and GLWE ciphertexts to use the same modulus.
    #[error("LWE/GLWE ciphertext modulus mismatch: LWE uses {lwe:?}, GLWE uses {glwe:?}")]
    CiphertextModulusMismatch {
        /// Small-LWE ciphertext modulus.
        lwe: T,
        /// GLWE ciphertext modulus.
        glwe: T,
    },
}
