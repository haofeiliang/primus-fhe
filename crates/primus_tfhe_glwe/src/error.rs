//! Errors owned by the GLWE TFHE parameter, client and key-generation boundaries.

use crate::PbsOrder;
use primus_decompose::ApproxSignedBasisError;
use primus_glwe::GlevParameterError;

/// An invalid combination of GLWE-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheParameterError {
    /// Classic blind rotation supports binary and ternary input LWE secrets.
    #[error("TFHE bootstrapping requires a binary or ternary input LWE secret key")]
    UnsupportedInputLweSecretKey,

    /// The rotation domain `2N` cannot be represented by the input coefficient type.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,

    /// The LWE ciphertext and GLWE accumulator use different plaintext spaces.
    #[error("LWE and GLWE plaintext moduli must match")]
    PlainModulusMismatch,

    /// The bootstrapping basis or gadget layout is incompatible with the accumulator.
    #[error("invalid GLWE bootstrapping parameters: {0}")]
    BootstrappingParameters(#[source] GlevParameterError),

    /// The small LWE key does not fit in the main GLWE key capacity and
    /// therefore cannot be represented as a padded GLWE key with `k' <= k`.
    #[error(
        "small LWE dimension {small_lwe_dimension} exceeds GLWE secret-key capacity {capacity}"
    )]
    SmallLweDimensionExceedsGlweCapacity {
        /// Configured small LWE dimension.
        small_lwe_dimension: usize,
        /// Main GLWE secret-key capacity `kN`.
        capacity: usize,
    },

    /// GLWE key switching and compact extraction require matching small-LWE
    /// and GLWE ciphertext moduli.
    #[error("TFHE GLWE key switching requires matching LWE and GLWE ciphertext moduli")]
    CipherModulusMismatch,

    /// The GLWE key-switching basis or output gadget layout is incompatible.
    #[error("invalid GLWE key-switching parameters: {0}")]
    KeySwitchingParameters(#[source] GlevParameterError),
}

/// An incompatibility between secret keys and TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// The client key was created for a different PBS order.
    #[error("PBS order mismatch: expected {expected:?}, got {actual:?}")]
    PbsOrderMismatch {
        /// PBS order required by the parameters.
        expected: PbsOrder,
        /// PBS order associated with the client key.
        actual: PbsOrder,
    },

    /// The LWE secret key has the wrong dimension.
    #[error("LWE secret-key dimension mismatch: expected {expected}, got {actual}")]
    LweDimensionMismatch {
        /// Dimension required by the parameters.
        expected: usize,
        /// Dimension found in the key.
        actual: usize,
    },

    /// The LWE secret-key distribution does not match the parameters.
    #[error("LWE secret-key distribution mismatch")]
    LweSecretKeyDistributionMismatch,

    /// The GLWE secret key has the wrong dimension.
    #[error("GLWE secret-key dimension mismatch: expected {expected}, got {actual}")]
    GlweDimensionMismatch {
        /// Dimension required by the parameters.
        expected: usize,
        /// Dimension found in the key.
        actual: usize,
    },

    /// The GLWE secret key has the wrong polynomial length.
    #[error("GLWE polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the parameters.
        expected: usize,
        /// Polynomial length found in the key.
        actual: usize,
    },

    /// The GLWE secret-key distribution does not match the parameters.
    #[error("GLWE secret-key distribution mismatch")]
    GlweSecretKeyDistributionMismatch,
}

/// An error produced by the raw TFHE client API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheClientError {
    /// The public key has the wrong external LWE dimension.
    #[error("public-key LWE dimension mismatch: expected {expected}, got {actual}")]
    PublicKeyDimensionMismatch {
        /// Required external LWE dimension.
        expected: usize,
        /// Supplied public-key dimension.
        actual: usize,
    },
    /// The public key uses a different ciphertext modulus.
    #[error("public-key ciphertext modulus mismatch")]
    PublicKeyModulusMismatch,
    /// The client key does not match the parameter set.
    #[error(transparent)]
    IncompatibleKey(#[from] TfheKeyError),

    /// The input message is outside the plaintext domain `[0, t)`.
    #[error("message is outside the plaintext domain")]
    MessageOutOfRange,

    /// The input message sets the padding half of the plaintext domain.
    #[error("message is outside the padded plaintext domain")]
    MessageOutsidePaddedDomain,

    /// A ciphertext belongs to a different LWE dimension.
    #[error("LWE ciphertext dimension mismatch: expected {expected}, got {actual}")]
    CiphertextDimensionMismatch {
        /// Required LWE dimension.
        expected: usize,
        /// Actual LWE dimension.
        actual: usize,
    },
}

/// An error produced by Boolean client construction, encryption or decryption.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BooleanError {
    /// Gate bootstrapping uses the 0/1 encoding modulo 4.
    #[error("Boolean TFHE requires plaintext modulus 4")]
    PlaintextModulusMustBeFour,

    /// A decrypted value is neither 0 nor 1 under plaintext modulus 4.
    #[error("decrypted value is not a valid Boolean plaintext")]
    InvalidPlaintext,

    /// Raw client-side encryption or decryption failed.
    #[error(transparent)]
    Client(#[from] TfheClientError),
}

/// An invalid circuit-bootstrapping parameter set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// The configured output radix or retained-level count is invalid.
    #[error("invalid circuit-bootstrap output basis: {0}")]
    InvalidOutputBasis(#[from] ApproxSignedBasisError),
    /// A configured key decomposition or derived gadget layout is invalid.
    #[error("invalid circuit-bootstrap {role} parameters: {source}")]
    GadgetParameters {
        /// Key role: trace or scheme-switch.
        role: &'static str,
        /// Invalid basis or gadget layout.
        #[source]
        source: primus_glwe::GlevParameterError,
    },
    /// The output basis belongs to another explicit or native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
    /// A gadget parameter set uses a different GLWE dimension or polynomial
    /// length from the TFHE accumulator.
    #[error("circuit-bootstrap {role} GLWE layout does not match the TFHE accumulator")]
    GlweLayoutMismatch {
        /// Role of the incompatible gadget parameter set.
        role: &'static str,
    },
    /// A gadget parameter set uses a different ciphertext modulus.
    #[error("circuit-bootstrap {role} modulus does not match the TFHE accumulator")]
    CipherModulusMismatch {
        /// Role of the incompatible gadget parameter set.
        role: &'static str,
    },
    /// The output layout overflows or has too many levels for one PBSManyLUT.
    #[error("circuit-bootstrap output decomposition does not fit in the accumulator")]
    OutputDecompositionTooLarge,
}

/// Failure to generate ordinary or circuit-bootstrap keys for this TFHE family.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyGenerationError {
    /// The supplied client secrets do not match the TFHE parameters.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
    /// Sparse blind-rotation key generation failed.
    #[error(transparent)]
    SparseBootstrapping(#[from] SparseBootstrappingKeyError),
    /// The requested CBS configuration cannot be prepared.
    #[error(transparent)]
    CircuitBootstrapParameters(#[from] CircuitBootstrapParameterError),
    /// Prepared CBS parameters belong to another accumulator or input domain.
    #[error("circuit-bootstrap parameters do not match this TFHE context")]
    IncompatibleCircuitBootstrapParameters,
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
    /// Public bucket-map validation or private matching failed.
    #[error(transparent)]
    BucketMap(#[from] primus_tfhe::sparse::BucketMapError),
    /// Actual secret coefficients are not binary or do not have the declared weight.
    #[error("small-LWE coefficients do not match the declared binary Hamming weight")]
    InvalidSecretCoefficients,
    /// GGSW ciphertext storage lengths exceed addressable allocation sizes.
    #[error("sparse GGSW storage size overflow")]
    StorageSizeOverflow,
}
