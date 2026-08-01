use thiserror::Error;

/// Error type for the [`primus_distr`](crate) crate.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum DistrErr {
    /// The standard deviation is unsupported by the floating-point kernels.
    #[error("standard deviation must be at least 0.7 with finite variance, got {value}")]
    InvalidStandardDeviation {
        /// Invalid standard deviation.
        value: f64,
    },

    /// The tail cut is non-finite or not positive.
    #[error("tail cut must be finite and positive, got {value}")]
    InvalidTailCut {
        /// Invalid tail cut.
        value: f64,
    },

    /// The truncated support cannot be represented as a `u64` magnitude.
    #[error(
        "Gaussian support is too large for standard deviation {standard_deviation} and tail cut {tail_cut}"
    )]
    MaximumMagnitudeTooLarge {
        /// Requested standard deviation.
        standard_deviation: f64,
        /// Requested tail cut.
        tail_cut: f64,
    },

    /// The requested support exceeds a CDT backend's table limit.
    #[error(
        "maximum magnitude {maximum_magnitude} exceeds the CDT backend limit {supported_maximum}"
    )]
    CdtTableTooLarge {
        /// Requested maximum magnitude.
        maximum_magnitude: u64,
        /// Largest magnitude supported by the backend.
        supported_maximum: u64,
    },

    /// The modular output cannot encode every supported magnitude.
    #[error(
        "maximum magnitude {maximum_magnitude} must not exceed modulus minus one {modulus_minus_one}"
    )]
    ModulusTooSmall {
        /// Requested maximum magnitude.
        maximum_magnitude: u64,
        /// Supplied modulus minus one.
        modulus_minus_one: u128,
    },

    /// The signed output type cannot represent every supported magnitude.
    #[error("maximum magnitude {maximum_magnitude} exceeds output type maximum {output_maximum}")]
    OutputTypeTooNarrow {
        /// Requested maximum magnitude.
        maximum_magnitude: u64,
        /// Largest positive value of the output type.
        output_maximum: u128,
    },

    /// A signed sampler was requested with an unsigned output type.
    #[error("signed Gaussian sampling requires a signed output type")]
    UnsignedOutputType,

    /// Ziggurat setup could not represent the requested distribution.
    #[error(
        "cannot construct Ziggurat for standard deviation {standard_deviation} and tail cut {tail_cut}"
    )]
    ZigguratConstructionFailed {
        /// Requested standard deviation.
        standard_deviation: f64,
        /// Requested tail cut.
        tail_cut: f64,
    },
}
