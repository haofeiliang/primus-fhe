/// Errors returned when constructing a multi-limb approximate signed basis.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BigUintApproxSignedBasisError {
    /// The logarithm of the decomposition basis is outside the supported range.
    #[error("log_basis must satisfy 0 < log_basis < {limb_bits}, got {log_basis}")]
    InvalidLogBasis {
        /// Requested base-2 logarithm.
        log_basis: u32,
        /// Bit width of one modulus limb.
        limb_bits: u32,
    },
    /// The decomposition basis is larger than the modulus.
    #[error("decomposition basis must not exceed the modulus")]
    BasisExceedsModulus,
    /// The requested retained decomposition length is zero.
    #[error("reverse_length must be greater than zero")]
    ZeroReverseLength,
    /// The requested retained decomposition length exceeds the full length.
    #[error(
        "reverse_length must not exceed the full decomposition length {full_length}, got {reverse_length}"
    )]
    ReverseLengthTooLarge {
        /// Requested retained level count.
        reverse_length: usize,
        /// Maximum level count for this modulus and basis.
        full_length: usize,
    },
}
