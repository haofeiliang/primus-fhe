//! GLWE key switching across single-modulus and RNS representations.

mod dcrt;
mod fourier;
mod hybrid;
mod ntt;

/// An incompatible GLWE key-switching key, domain, ciphertext, or workspace.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlweKeySwitchingError {
    /// The key was generated for different parameters or a different modulus.
    #[error("key-switching key and gadget domain do not match")]
    KeyDomainMismatch,
    /// The reusable workspace has the wrong output layout.
    #[error("key-switching context and gadget domain do not match")]
    ContextMismatch,
    /// The input ciphertext length differs from the key input layout.
    #[error("input GLWE length mismatch: expected {expected}, got {actual}")]
    InputLengthMismatch {
        /// Length required by the key.
        expected: usize,
        /// Supplied ciphertext length.
        actual: usize,
    },
    /// The output ciphertext length differs from the domain output layout.
    #[error("output GLWE length mismatch: expected {expected}, got {actual}")]
    OutputLengthMismatch {
        /// Length required by the domain.
        expected: usize,
        /// Supplied ciphertext length.
        actual: usize,
    },
    /// A full expansion was given the wrong number of output ciphertexts.
    #[error("output ciphertext count mismatch: expected {expected}, got {actual}")]
    OutputCountMismatch {
        /// Number of output ciphertexts required by the operation.
        expected: usize,
        /// Number of output ciphertexts supplied by the caller.
        actual: usize,
    },
    /// A partial expansion count is not a supported power of two.
    #[error("invalid expansion count {actual}; expected a power of two no greater than {maximum}")]
    InvalidExpansionCount {
        /// Largest supported expansion count.
        maximum: usize,
        /// Number of output ciphertexts supplied by the caller.
        actual: usize,
    },
}

pub use dcrt::{DcrtGlweKeySwitchingContext, DcrtGlweKeySwitchingError, DcrtGlweKeySwitchingKey};
pub use fourier::{FourierGlweKeySwitchingContext, FourierGlweKeySwitchingKey};
pub use hybrid::{HybridRnsGlweKeySwitchingContext, HybridRnsGlweKeySwitchingKey};
pub use ntt::{NttGlweKeySwitchingContext, NttGlweKeySwitchingKey};
