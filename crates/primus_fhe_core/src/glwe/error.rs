/// Errors returned while constructing a GLWE secret key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlweSecretKeyError {
    /// The source LWE secret key is empty.
    #[error("LWE secret-key dimension must be non-zero")]
    ZeroLweDimension,

    /// The requested polynomial length is not supported.
    #[error("GLWE polynomial length must be a power of two greater than one, got {poly_length}")]
    InvalidPolynomialLength {
        /// Requested polynomial length.
        poly_length: usize,
    },

    /// Rounding the LWE dimension up to a complete polynomial overflowed
    /// `usize`.
    #[error(
        "padded GLWE secret-key capacity overflow for LWE dimension {lwe_dimension} and polynomial length {poly_length}"
    )]
    CapacityOverflow {
        /// Source LWE dimension.
        lwe_dimension: usize,
        /// Requested polynomial length.
        poly_length: usize,
    },
}
