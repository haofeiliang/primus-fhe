use std::fmt::Debug;

use thiserror::Error;

/// Invalid NTT table geometry, coefficient range or root of unity.
#[derive(Error, Debug)]
pub enum NttError<T> {
    /// NTT tables require at least two polynomial coefficients.
    #[error("NTT polynomial length must be at least two (log_n >= 1)")]
    PolynomialLengthTooSmall,
    /// Error that occurs when the given modulus has no primitive root with the given degree.
    #[error("no primitive root of degree {degree:?} exists modulo {modulus:?}")]
    NoPrimitiveRoot {
        /// The degree for the primitive root
        degree: T,
        /// The modulus.
        modulus: T,
    },
    /// The requested degree does not fit the table's coefficient type.
    #[error("degree {degree} is not representable by the coefficient type for modulus {modulus:?}")]
    DegreeNotRepresentable {
        /// degree
        degree: usize,
        /// modulus
        modulus: T,
    },
    /// Error that occurs when the degree is too large.
    #[error("degree must be less than modulus: {degree} >= {modulus:?}")]
    DegreeTooLarge {
        /// degree
        degree: usize,
        /// modulus
        modulus: T,
    },
    /// Error that occurs when the modulus is too large for lazy NTT arithmetic.
    #[error("modulus {modulus} is too large for this NTT table (requires modulus < 2^{max_bits})")]
    ModulusTooLarge {
        /// The modulus value.
        modulus: T,
        /// The maximum supported bit-width for this table type.
        max_bits: u32,
    },
}
