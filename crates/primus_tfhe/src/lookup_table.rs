use core::fmt;

use primus_fhe_core::plaintext::{PlaintextCodec, PlaintextEmbedding};
use primus_integer::FheUint;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::RingContext;

use crate::backend_support::modulus_switch;

/// A lookup table compiled into an encoded negacyclic polynomial.
///
/// An execution backend embeds this polynomial into its accumulator
/// representation when blind rotation begins.
#[derive(Clone)]
#[repr(transparent)]
pub struct LookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
}

impl<T: FheUint> fmt::Debug for LookupTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LookupTable")
            .field("coefficient_count", &self.polynomial.as_ref().len())
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> LookupTable<T> {
    /// Returns the encoded lookup-table polynomial.
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Decomposes this table into its encoded polynomial.
    #[inline]
    pub fn into_polynomial(self) -> PolynomialOwned<T> {
        self.polynomial
    }
}

/// Returns the independently programmable front-half plaintext-domain length.
#[doc(hidden)]
pub fn lookup_table_domain_len<T: FheUint>(
    plaintext_modulus: T,
    poly_length: usize,
) -> Result<usize, LookupTableError> {
    let plaintext_domain_len: usize = plaintext_modulus
        .try_into()
        .map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
    let domain_len = plaintext_domain_len.div_ceil(2);
    if domain_len > poly_length {
        return Err(LookupTableError::PlaintextDomainTooLarge {
            domain_len,
            rotation_domain_len: poly_length,
        });
    }
    Ok(domain_len)
}

/// Compiles already encoded outputs into a negacyclic lookup-table polynomial.
///
/// This cross-crate helper is hidden because family parameter types should own
/// the user-facing compilation API and supply their validated codecs and
/// moduli.
#[doc(hidden)]
pub fn compile_encoded_lookup_table<T, M, F>(
    domain_len: usize,
    poly_length: usize,
    lwe_codec: &PlaintextCodec<T>,
    lwe_modulus: Option<T>,
    accumulator_modulus: M,
    encoded_output_at: F,
) -> Result<LookupTable<T>, LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    F: Fn(usize) -> Result<T, LookupTableError>,
{
    let two_n = poly_length * 2;
    let rotation_center = |input: usize| -> Result<usize, LookupTableError> {
        let input = T::try_from(input).map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
        let encoded = lwe_codec.encode_value(input, PlaintextEmbedding::Unsigned);
        Ok(modulus_switch(encoded, lwe_modulus, two_n))
    };

    let mut polynomial = Polynomial::zero(poly_length);
    let coefficients = polynomial.as_mut();
    let first_output = encoded_output_at(0)?;
    let mut encoded_output = first_output;
    let mut previous_center = 0;
    let mut cursor = 0;

    for input in 1..domain_len {
        let center = rotation_center(input)?;
        if previous_center >= center {
            return Err(LookupTableError::RotationCenterCollision {
                first_input: input - 1,
                second_input: input,
                exponent: center,
            });
        }
        let boundary = upper_midpoint(previous_center, center);
        coefficients[cursor..boundary].fill(encoded_output);
        cursor = boundary;
        encoded_output = encoded_output_at(input)?;
        previous_center = center;
    }

    let next_center = rotation_center(domain_len)?;
    if previous_center >= next_center {
        return Err(LookupTableError::RotationCenterCollision {
            first_input: domain_len - 1,
            second_input: domain_len,
            exponent: next_center,
        });
    }
    let boundary = upper_midpoint(previous_center, next_center).min(poly_length);
    coefficients[cursor..boundary].fill(encoded_output);
    coefficients[boundary..].fill(accumulator_modulus.reduce_neg(first_output));
    Ok(LookupTable { polynomial })
}

/// Returns the integer midpoint of `lhs` and `rhs`, rounding upward.
#[inline]
fn upper_midpoint(lhs: usize, rhs: usize) -> usize {
    lhs.midpoint(rhs) + ((lhs ^ rhs) & 1)
}

/// An error produced while compiling a TFHE lookup table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupTableError {
    /// The plaintext modulus cannot be used as a platform-sized domain length.
    #[error("plaintext modulus is too large for lookup-table compilation")]
    PlaintextModulusTooLarge,
    /// More plaintext values exist than available rotation coefficients.
    #[error(
        "plaintext domain of length {domain_len} exceeds rotation domain of length {rotation_domain_len}"
    )]
    PlaintextDomainTooLarge {
        /// Number of independently programmable plaintext inputs.
        domain_len: usize,
        /// Number of accumulator coefficients.
        rotation_domain_len: usize,
    },
    /// Adjacent messages collide after encoding and modulus switching.
    #[error(
        "rotation-center collision between inputs {first_input} and {second_input} at exponent {exponent}"
    )]
    RotationCenterCollision {
        /// First adjacent plaintext input.
        first_input: usize,
        /// Second adjacent plaintext input.
        second_input: usize,
        /// Colliding rotation exponent.
        exponent: usize,
    },
    /// A slice has the wrong front-half domain length.
    #[error("lookup-table domain length mismatch: expected {expected}, got {actual}")]
    DomainLengthMismatch {
        /// Required output count.
        expected: usize,
        /// Supplied output count.
        actual: usize,
    },
    /// A function output lies outside the plaintext domain.
    #[error("lookup-table output for input {input} is outside the plaintext domain")]
    OutputOutOfRange {
        /// Input whose output is invalid.
        input: usize,
    },
}
