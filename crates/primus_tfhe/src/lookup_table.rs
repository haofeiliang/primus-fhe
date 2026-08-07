use core::fmt;

use primus_integer::FheUint;
use primus_poly::{Polynomial, PolynomialOwned};
use primus_reduce::RingContext;

use crate::backend_support::modulus_switch;
use crate::{PlaintextEmbedding, TfheParameters};

/// A lookup table compiled into an encoded negacyclic polynomial.
///
/// User functions are fully evaluated during compilation. Applying this table
/// therefore requires neither a callback nor dynamic dispatch on the PBS hot
/// path. An execution backend embeds this polynomial into its accumulator
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

impl<T, LM, GM> TfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Compiles a unary function over the front half of the plaintext domain.
    ///
    /// If the complete encoding modulus is `t`, the function is evaluated for
    /// inputs in `[0, ceil(t / 2))`. The accumulator extends it beyond the
    /// front half by negacyclicity. Consequently, an arbitrary function
    /// requires its input to remain in this front half, while a negacyclic
    /// function can use the complete plaintext domain.
    pub fn compile_lookup_table_fn<F>(
        &self,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        let domain_len = self.lookup_table_domain_len()?;
        self.compile_lookup_table_outputs(domain_len, function)
    }

    /// Compiles one output value for every input in `[0, ceil(t / 2))`.
    ///
    /// The upper half is the negacyclic extension of these values; see
    /// [`Self::compile_lookup_table_fn`].
    pub fn compile_lookup_table_slice(
        &self,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError> {
        let domain_len = self.lookup_table_domain_len()?;
        if outputs.len() != domain_len {
            return Err(LookupTableError::DomainLengthMismatch {
                expected: domain_len,
                actual: outputs.len(),
            });
        }
        self.compile_lookup_table_outputs(domain_len, |input| outputs[input])
    }

    /// Returns the number of independently programmable lookup-table inputs.
    ///
    /// A negacyclic accumulator determines its second half from its first, so
    /// only `ceil(t / 2)` values are stored for plaintext modulus `t`. Each
    /// value must also have a distinct location in the `N`-coefficient
    /// rotation domain.
    fn lookup_table_domain_len(&self) -> Result<usize, LookupTableError> {
        let plaintext_domain_len: usize = self
            .plain_modulus_value()
            .try_into()
            .map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
        let domain_len = plaintext_domain_len.div_ceil(2);
        let rotation_domain_len = self.glwe().poly_length();
        if domain_len > rotation_domain_len {
            return Err(LookupTableError::PlaintextDomainTooLarge {
                domain_len,
                rotation_domain_len,
            });
        }
        Ok(domain_len)
    }

    /// Evaluates plaintext outputs and encodes them for accumulator storage.
    ///
    /// This wrapper owns validation of the user-visible output range. The
    /// lower-level compiler consequently receives values already represented
    /// in the GLWE ciphertext modulus.
    fn compile_lookup_table_outputs<F>(
        &self,
        domain_len: usize,
        output_at: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        let plaintext_modulus = self.plain_modulus_value();
        let codec = self.glwe().plaintext_codec();
        self.compile_encoded_lookup_table(domain_len, |input| {
            let output = output_at(input);
            if output >= plaintext_modulus {
                Err(LookupTableError::OutputOutOfRange { input })
            } else {
                Ok(codec.encode_value(output, PlaintextEmbedding::Unsigned))
            }
        })
    }

    /// Compiles encoded outputs into the negacyclic accumulator polynomial.
    ///
    /// `domain_len` is the independently programmable front-half domain and
    /// `encoded_output_at` returns coefficients in the GLWE ciphertext
    /// modulus. Adjacent plaintext inputs are mapped to rotation centers; the
    /// coefficients between their upper midpoints are filled with the output
    /// belonging to the preceding center. The tail is the negation of the
    /// first output, which supplies the required negacyclic continuation.
    ///
    /// This is `pub(crate)` so TFHE parameter construction can also compile
    /// outputs that already use a backend-defined encoding without exposing
    /// that representation-sensitive operation to users.
    pub(crate) fn compile_encoded_lookup_table<F>(
        &self,
        domain_len: usize,
        encoded_output_at: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> Result<T, LookupTableError>,
    {
        let poly_length = self.glwe().poly_length();
        let two_n = poly_length * 2;
        let lwe_codec = self.small_lwe().plaintext_codec();
        let lwe_modulus = self.small_lwe().cipher_modulus().explicit_value();
        let rotation_center = |input: usize| -> Result<usize, LookupTableError> {
            let input =
                T::try_from(input).map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
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

        coefficients[boundary..].fill(self.glwe().cipher_modulus().reduce_neg(first_output));

        Ok(LookupTable { polynomial })
    }
}

/// Returns the integer midpoint of `lhs` and `rhs`, rounding upward.
///
/// Lookup-table intervals use this value as the boundary between adjacent
/// rotation centers, assigning an odd-width tie to the center on the left.
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

    /// More user-visible plaintext values exist than available coefficients.
    #[error(
        "plaintext domain of length {domain_len} exceeds rotation domain of length {rotation_domain_len}"
    )]
    PlaintextDomainTooLarge {
        /// Number of plaintext inputs.
        domain_len: usize,
        /// Number of accumulator coefficients, equal to `N`.
        rotation_domain_len: usize,
    },

    /// Adjacent messages are not distinguishable after encoding and modulus
    /// switching.
    #[error(
        "rotation-center collision between inputs {first_input} and {second_input} at exponent {exponent}"
    )]
    RotationCenterCollision {
        /// First adjacent plaintext input.
        first_input: usize,
        /// Second adjacent plaintext input.
        second_input: usize,
        /// Colliding or wrapped rotation exponent.
        exponent: usize,
    },

    /// A slice does not contain exactly one output per front-half input.
    #[error("lookup-table domain length mismatch: expected {expected}, got {actual}")]
    DomainLengthMismatch {
        /// Plaintext-domain length.
        expected: usize,
        /// Supplied slice length.
        actual: usize,
    },

    /// A function output lies outside `[0, t)`.
    #[error("lookup-table output for input {input} is outside the plaintext domain")]
    OutputOutOfRange {
        /// Input whose output is invalid.
        input: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::upper_midpoint;

    #[test]
    fn upper_midpoint_rounds_up() {
        assert_eq!(upper_midpoint(3, 7), 5);
        assert_eq!(upper_midpoint(2, 5), 4);
    }
}
