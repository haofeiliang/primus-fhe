//! Errors produced by the NTT TFHE backend.

use primus_integer::FheUint;

pub use primus_tfhe::{LookupTableError, TfheEvaluationError};
pub use primus_tfhe_glwe::{
    BooleanError, CircuitBootstrapParameterError, KeyGenerationError, TfheClientError,
    TfheKeyError, TfheParameterError,
};

/// Failure to construct an NTT table or bind it to TFHE parameters.
#[derive(Debug, thiserror::Error)]
pub enum TfheContextError<T: FheUint> {
    /// The selected transform table could not be constructed.
    #[error("failed to construct transform table: {0}")]
    TransformTable(#[from] primus_ntt::NttError<T>),
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
}

/// Failure to construct an experimental sparse bootstrapping key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseBootstrappingKeyError {
    /// The client secrets do not match the context's parameters.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
    /// Sparse generation requires a fixed-weight binary small-LWE distribution.
    #[error("sparse bootstrapping requires a fixed-weight binary small-LWE secret")]
    UnsupportedSecretDistribution,
    /// The public weight must be positive and strictly less than the input dimension.
    #[error("sparse Hamming weight must satisfy 0 < h < n")]
    InvalidHammingWeight,
    /// There must be at least one copy and enough buckets for both copies and support.
    #[error("sparse mapping requires copy_count >= 1 and bucket_count >= max(copy_count, h)")]
    InvalidBucketParameters,
    /// Actual secret coefficients are not binary or do not have the declared weight.
    #[error("small-LWE coefficients do not match the declared binary Hamming weight")]
    InvalidSecretCoefficients,
    /// Mapping or GGSW storage lengths exceed addressable allocation sizes.
    #[error("sparse bootstrapping-key storage size overflow")]
    StorageSizeOverflow,
    /// None of eight independently sampled maps admitted a complete support matching.
    #[error("sparse support matching failed after eight attempts")]
    MatchingFailed,
}
