//! Errors owned by the NTRU TFHE parameter, client and key-generation boundaries.

use primus_decompose::ApproxSignedBasisError;
use primus_ntru::NlevParameterError;

/// An invalid combination of NTRU-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum TfheParameterError {
    /// Return-key encryption at external q has invalid sampling parameters.
    #[error("invalid return-key encryption parameters")]
    KeySwitchingEncryption(#[source] primus_lwe::LweParameterError),
    /// The configured accumulator layout, encoding or samplers are invalid.
    #[error("invalid accumulator parameters")]
    AccumulatorParameters(#[source] primus_ntru::NtruParameterError),
    /// Invalid NLev/NGSW decomposition or layout for blind rotation.
    #[error("invalid NTRU bootstrapping parameters")]
    BootstrappingParameters(#[source] NlevParameterError),
    /// Invalid decomposition at external q for the LWE return key.
    #[error("invalid LWE return key-switching parameters")]
    KeySwitchingParameters(#[source] ApproxSignedBasisError),
    /// The rotation domain `2N` cannot be represented by the input coefficient type.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,
    /// The external LWE distribution must be binary or ternary.
    #[error("NTRU TFHE requires a binary or ternary client secret-key distribution")]
    UnsupportedClientSecretKeyDistribution,
    /// The LWE and NTRU plaintext spaces differ.
    #[error("LWE and NTRU plaintext moduli do not match")]
    PlainModulusMismatch,
}

/// An incompatibility between NTRU client keys and TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// At least one NTRU secret has the wrong polynomial length.
    #[error("NTRU client-key polynomial length mismatch")]
    PolynomialLengthMismatch,
    /// The external LWE secret has a different distribution label.
    #[error("NTRU client secret-key distribution mismatch")]
    ClientSecretKeyDistributionMismatch,
    /// An external LWE coefficient is outside the declared binary or ternary domain.
    #[error("NTRU TFHE client coefficients do not match their binary or ternary domain")]
    InvalidClientSecretKeyCoefficient,
    /// The external secret has the wrong LWE dimension.
    #[error("NTRU client key has the wrong external LWE dimension")]
    ExternalLweDimensionMismatch,
    /// A signed accumulator coefficient cannot be represented by the return key at q.
    #[error("accumulator secret magnitude must be less than the external LWE modulus")]
    AccumulatorSecretOutsideLweModulus,
    /// The accumulator key distribution differs from its parameter set.
    #[error("NTRU accumulator secret-key distribution mismatch")]
    AccumulatorSecretKeyDistributionMismatch,
}

/// A failure to construct a family client or prepare its secret representation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheClientError {
    /// The client key does not match the parameter set.
    #[error(transparent)]
    IncompatibleKey(#[from] TfheKeyError),
    /// The selected LWE key does not match its external domain.
    #[error(transparent)]
    Client(#[from] primus_tfhe::ClientError),
    /// The Boolean client requires plaintext modulus four.
    #[error(transparent)]
    Boolean(#[from] primus_tfhe::BooleanError),
    /// Preparing the accumulator secret representation failed.
    #[error("NTRU accumulator secret conversion failed")]
    Ntru(#[from] primus_ntru::NtruError),
}

/// An incompatible circuit-bootstrap parameter set.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CircuitBootstrapParameterError {
    /// Trace or scheme-switch encryption parameters are invalid.
    #[error("invalid circuit-bootstrap {role} encryption parameters")]
    EncryptionParameters {
        /// Key role: trace or scheme-switch.
        role: &'static str,
        /// Invalid ring encoding or sampler configuration.
        #[source]
        source: primus_ntru::NtruParameterError,
    },
    /// The configured output radix or retained-level count is invalid.
    #[error("invalid circuit-bootstrap output basis")]
    InvalidOutputBasis(#[from] ApproxSignedBasisError),
    /// A configured key decomposition or derived gadget layout is invalid.
    #[error("invalid circuit-bootstrap {role} parameters")]
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
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
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
    #[error("NTRU key generation or conversion failed")]
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
