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

/// Multiple lookup tables interleaved into one negacyclic accumulator.
///
/// `output_count` is a power of two. Blind rotation quantizes every rotation
/// exponent to a multiple of that count, so each residue class contains an
/// independently programmable lookup table.
#[derive(Clone)]
pub struct ManyLookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    output_count: usize,
}

impl<T: FheUint> fmt::Debug for ManyLookupTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManyLookupTable")
            .field("coefficient_count", &self.polynomial.as_ref().len())
            .field("output_count", &self.output_count)
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> ManyLookupTable<T> {
    /// Returns the interleaved encoded lookup-table polynomial.
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Returns the number of independently programmable outputs.
    #[inline]
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// Decomposes this table into its polynomial and output count.
    #[inline]
    pub fn into_parts(self) -> (PolynomialOwned<T>, usize) {
        (self.polynomial, self.output_count)
    }
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

/// Compiles encoded multi-output values into an interleaved negacyclic lookup
/// table.
///
/// The polynomial is split into `output_count` residue classes. Each class is
/// compiled as a lookup table of length `poly_length / output_count`. This is
/// the accumulator layout consumed by windowed modulus switching in
/// PBSManyLUT.
#[doc(hidden)]
pub fn compile_encoded_many_lookup_table<T, M, F>(
    domain_len: usize,
    poly_length: usize,
    output_count: usize,
    lwe_codec: &PlaintextCodec<T>,
    lwe_modulus: Option<T>,
    accumulator_modulus: M,
    encoded_output_at: F,
) -> Result<ManyLookupTable<T>, LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    if output_count == 0 || !output_count.is_power_of_two() {
        return Err(LookupTableError::OutputCountMustBePowerOfTwo { output_count });
    }
    if output_count > poly_length {
        return Err(LookupTableError::OutputCountTooLarge {
            output_count,
            poly_length,
        });
    }

    let virtual_poly_length = poly_length / output_count;
    if domain_len > virtual_poly_length {
        return Err(LookupTableError::PlaintextDomainTooLarge {
            domain_len,
            rotation_domain_len: virtual_poly_length,
        });
    }

    let mut polynomial = PolynomialOwned::zero(poly_length);
    for output_index in 0..output_count {
        let table = compile_encoded_lookup_table(
            domain_len,
            virtual_poly_length,
            lwe_codec,
            lwe_modulus,
            accumulator_modulus,
            |input| encoded_output_at(input, output_index),
        )?;
        for (destination, &value) in polynomial.as_mut()[output_index..]
            .iter_mut()
            .step_by(output_count)
            .zip(table.polynomial().as_ref())
        {
            *destination = value;
        }
    }

    Ok(ManyLookupTable {
        polynomial,
        output_count,
    })
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
    /// The flattened PBSManyLUT table length does not fit in `usize`.
    #[error("many-LUT flattened table length overflows usize")]
    ManyTableLengthOverflow,
    /// PBSManyLUT requires a non-zero power-of-two output count.
    #[error("many-LUT output count {output_count} is not a non-zero power of two")]
    OutputCountMustBePowerOfTwo {
        /// Supplied output count.
        output_count: usize,
    },
    /// The requested number of outputs exceeds the accumulator length.
    #[error("many-LUT output count {output_count} exceeds polynomial length {poly_length}")]
    OutputCountTooLarge {
        /// Supplied output count.
        output_count: usize,
        /// Accumulator polynomial length.
        poly_length: usize,
    },
    /// A function output lies outside the plaintext domain.
    #[error("lookup-table output for input {input} is outside the plaintext domain")]
    OutputOutOfRange {
        /// Input whose output is invalid.
        input: usize,
    },
}
