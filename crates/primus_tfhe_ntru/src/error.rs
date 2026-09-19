//! Errors owned by the NTRU TFHE parameter, client and key-generation boundaries.

use primus_decompose::ApproxSignedBasisError;
use primus_ntru::NlevParameterError;

/// An invalid combination of NTRU-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheParameterError {
    /// Invalid NLev/NGSW decomposition or layout for blind rotation.
    #[error("invalid NTRU bootstrapping parameters: {0}")]
    BootstrappingParameters(#[source] NlevParameterError),
    /// Invalid NLev decomposition or layout for the NTRU key switch.
    #[error("invalid NTRU key-switching parameters: {0}")]
    KeySwitchingParameters(#[source] NlevParameterError),
    /// The rotation domain `2N` cannot be represented by the input coefficient type.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,
    /// The external LWE and client NTRU distributions must be binary or ternary.
    #[error("NTRU TFHE requires a binary or ternary client secret-key distribution")]
    UnsupportedClientSecretKeyDistribution,
    /// The external LWE and padded NTRU views describe different distributions.
    #[error("the external LWE and client NTRU secret-key distributions must match")]
    ClientSecretKeyDistributionMismatch,
    /// The external LWE key cannot fit in one zero-padded NTRU polynomial.
    #[error("external LWE dimension {lwe_dimension} must belong to 1..={poly_length}")]
    InvalidLweDimension {
        /// Configured external LWE dimension.
        lwe_dimension: usize,
        /// Configured NTRU polynomial length.
        poly_length: usize,
    },
    /// The accumulator and key-switching rings have different lengths.
    #[error("NTRU polynomial lengths do not match")]
    PolynomialLengthMismatch,
    /// The LWE and NTRU plaintext spaces differ.
    #[error("LWE and NTRU plaintext moduli do not match")]
    PlainModulusMismatch,
    /// The LWE and NTRU ciphertext rings differ.
    #[error("LWE and NTRU ciphertext moduli do not match")]
    CipherModulusMismatch,
}

/// An incompatibility between NTRU client keys and TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// At least one NTRU secret has the wrong polynomial length.
    #[error("NTRU client-key polynomial length mismatch")]
    PolynomialLengthMismatch,
    /// The client NTRU secret was sampled from a different distribution.
    #[error("NTRU client secret-key distribution mismatch")]
    ClientSecretKeyDistributionMismatch,
    /// An active coefficient is outside the declared binary or ternary domain.
    #[error("NTRU TFHE client coefficients do not match their binary or ternary domain")]
    InvalidClientSecretKeyCoefficient,
    /// The active client-key prefix has the wrong LWE dimension.
    #[error("NTRU client key has the wrong external LWE dimension")]
    ExternalLweDimensionMismatch,
    /// At least one coefficient after the active LWE prefix is nonzero.
    #[error("NTRU client key has a nonzero coefficient in its padded suffix")]
    ClientSecretKeyPaddingMismatch,
    /// The accumulator key distribution differs from its parameter set.
    #[error("NTRU accumulator secret-key distribution mismatch")]
    AccumulatorSecretKeyDistributionMismatch,
}

/// An error produced by the NTRU TFHE client API.
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
    /// The message is outside `[0, t)`.
    #[error("message is outside the plaintext domain")]
    MessageOutOfRange,
    /// The message violates the input-padding convention.
    #[error("message is outside the programmable padded domain")]
    MessageOutsidePaddedDomain,
    /// The ciphertext has the wrong LWE dimension.
    #[error("ciphertext LWE dimension mismatch: expected {expected}, got {actual}")]
    CiphertextDimensionMismatch {
        /// Expected external LWE dimension.
        expected: usize,
        /// Supplied LWE dimension.
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

/// An incompatible circuit-bootstrap parameter set.
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
        source: primus_ntru::NlevParameterError,
    },
    /// The output basis belongs to another explicit or native modulus.
    #[error("circuit-bootstrap output basis modulus does not match the accumulator")]
    OutputBasisModulusMismatch,
    /// A gadget parameter set uses another ring length.
    #[error("circuit-bootstrap {role} polynomial length differs from the accumulator")]
    PolynomialLengthMismatch {
        /// The incompatible parameter role.
        role: &'static str,
    },
    /// A gadget parameter set uses another ciphertext modulus.
    #[error("circuit-bootstrap {role} modulus differs from the accumulator")]
    CipherModulusMismatch {
        /// The incompatible parameter role.
        role: &'static str,
    },
    /// The LUT padded output count leaves too few programmable input slots.
    #[error("circuit-bootstrap output levels do not fit the ManyLUT accumulator")]
    OutputDecompositionTooLarge,
    /// Trace normalization requires an odd field modulus with Shoup headroom.
    #[error("circuit-bootstrap trace requires odd q below 2^(T::BITS-1)")]
    UnsupportedTraceModulus,
}

/// Failure to generate classic, sparse or circuit-bootstrap keys for this TFHE family.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyGenerationError {
    /// Sparse blind-rotation key generation failed.
    #[error(transparent)]
    SparseBootstrapping(#[from] SparseBootstrappingKeyError),
    /// The supplied client secrets do not match the TFHE parameters.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
    /// The requested CBS configuration cannot be prepared.
    #[error(transparent)]
    CircuitBootstrapParameters(#[from] CircuitBootstrapParameterError),
    /// Prepared CBS parameters belong to another accumulator or input domain.
    #[error("circuit-bootstrap parameters do not match this TFHE context")]
    IncompatibleCircuitBootstrapParameters,
    /// NTRU rejection sampling or transform conversion failed.
    #[error("NTRU key generation or conversion failed: {0}")]
    Ntru(#[from] primus_ntru::NtruError),
}

/// Failure to construct an experimental NTRU sparse bootstrapping key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SparseBootstrappingKeyError {
    /// Bucket selections require a fixed-weight binary client secret.
    #[error("sparse bootstrapping requires a fixed-weight binary client secret")]
    UnsupportedSecretDistribution,
    /// The public weight must satisfy `0 < h < n`.
    #[error("sparse Hamming weight must satisfy 0 < h < n")]
    InvalidHammingWeight,
    /// Actual client coefficients have a different weight from the declared one.
    #[error("client coefficients do not match the declared Hamming weight")]
    InvalidSecretWeight,
    /// Public map validation or private matching failed.
    #[error(transparent)]
    BucketMap(#[from] primus_tfhe::sparse::BucketMapError),
    /// Coefficient NGSW storage exceeds addressable allocation sizes.
    #[error("sparse NGSW storage size overflow")]
    StorageSizeOverflow,
}
