//! Compilation geometry for the current unsigned front-half input domain.
//!
//! Let `N` be the polynomial length, `s` the interleaving stride and `D` the
//! programmed prefix length. The virtual ring has `M = N / s` coefficients.
//! For message `m`, first encode `E(m) = round(m * q_in / t) mod q_in`, then
//! compute `c[m] = R(E(m), q_in, 2M)` using the rounding rule in
//! [`crate::backend_support`]. Both rounds have upward ties for unsigned input.
//! Combining the two rounds can move plateau boundaries.
//!
//! Append the terminating center
//! `c[D] = min(R(E(D), q_in, 2M), M)` with value `-f(0)`. Each position in
//! `0..M` receives the nearest center's value, with ties going to the higher
//! center. All centers, including the terminating one, must be strictly
//! increasing. This defines both the last plateau and the unprogrammed tail; the
//! latter is not an additional valid input domain. Negative rotation positions
//! use the ring's negacyclic extension.
//!
//! Lane `j` occupies coefficients `s*r + j`. Extracting coefficient `j` after
//! multiplying by `X^(-s*r)` reads that lane at virtual position `r`, negating
//! once for each crossing of `M`. Current ManyLUTs use `s = output_count`.

use core::fmt;

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};

use crate::backend_support::RotationQuantizer;

/// A lookup table compiled into an encoded negacyclic polynomial.
///
/// An execution backend embeds this polynomial into its accumulator
/// representation when blind rotation begins. Compilation binds the input's
/// unsigned rounded encoding and both ciphertext moduli. Output residues may
/// use a different scale, as required by Boolean and circuit bootstrapping.
/// The table does not bind a secret key, ciphertext dimension or backend.
#[derive(Clone)]
pub struct LookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    encoding: LookupTableEncoding<T>,
}

/// Multiple lookup tables interleaved into one negacyclic accumulator.
///
/// `output_count` is a power of two. Blind rotation quantizes every rotation
/// exponent to a multiple of that count, so each residue class contains an
/// independently programmable lookup table. This reduces the rotation resolution
/// and increases per-coefficient modulus-switch rounding error; it does not make
/// arbitrary full-domain functions programmable. Outputs are extracted at
/// coefficients `0..output_count`.
#[derive(Clone)]
pub struct ManyLookupTable<T: FheUint> {
    polynomial: PolynomialOwned<T>,
    encoding: LookupTableEncoding<T>,
    output_count: usize,
}

// The input encoding determines rotation centers; the accumulator modulus
// determines coefficient arithmetic. Output scale is deliberately independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LookupTableEncoding<T: FheUint> {
    input_plaintext_modulus: T,
    input_ciphertext_modulus: Option<T>,
    accumulator_modulus: Option<T>,
}

impl<T: FheUint> fmt::Debug for ManyLookupTable<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManyLookupTable")
            .field("coefficient_count", &self.polynomial.as_ref().len())
            .field("encoding", &self.encoding)
            .field("output_count", &self.output_count)
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> ManyLookupTable<T> {
    /// Checks the polynomial length and input/accumulator encoding domains.
    ///
    /// Output scale is not compared: raw Boolean and gadget-scaled outputs
    /// need not use the input plaintext codec. This does not validate the key,
    /// noise or actual plaintext of a raw input ciphertext.
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: usize,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        accumulator_modulus: Option<T>,
    ) -> bool {
        self.polynomial.as_ref().len() == poly_length
            && self.encoding
                == LookupTableEncoding {
                    input_plaintext_modulus,
                    input_ciphertext_modulus,
                    accumulator_modulus,
                }
    }

    /// Returns the interleaved encoded lookup-table polynomial.
    #[must_use]
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Returns the number of independently programmable outputs.
    #[must_use]
    #[inline]
    pub fn output_count(&self) -> usize {
        self.output_count
    }

    /// Decomposes this table into its polynomial and output count.
    #[must_use]
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
            .field("encoding", &self.encoding)
            .finish_non_exhaustive()
    }
}

impl<T: FheUint> LookupTable<T> {
    /// Checks the polynomial length and input/accumulator encoding domains.
    ///
    /// Output scale is not compared: raw Boolean and gadget-scaled outputs
    /// need not use the input plaintext codec. This does not validate the key,
    /// noise or actual plaintext of a raw input ciphertext.
    #[must_use]
    pub fn is_compatible(
        &self,
        poly_length: usize,
        input_plaintext_modulus: T,
        input_ciphertext_modulus: Option<T>,
        accumulator_modulus: Option<T>,
    ) -> bool {
        self.polynomial.as_ref().len() == poly_length
            && self.encoding
                == LookupTableEncoding {
                    input_plaintext_modulus,
                    input_ciphertext_modulus,
                    accumulator_modulus,
                }
    }

    /// Returns the encoded lookup-table polynomial.
    #[must_use]
    #[inline]
    pub fn polynomial(&self) -> &PolynomialOwned<T> {
        &self.polynomial
    }

    /// Decomposes this table into its encoded polynomial.
    #[must_use]
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
/// This cross-crate helper is hidden because family parameter types own the
/// user-facing compilation API and supply their validated parameters.
/// The input uses unsigned rounded encoding with
/// `input_plaintext_modulus` and `lwe_modulus`; raw outputs must be canonical
/// accumulator residues but may use any output scale. `domain_len` is a non-empty
/// prefix of the independently programmable front half. Only `0..domain_len`
/// has callback-defined values; the unprogrammed tail is not an additional
/// function domain. Invalid encoding, layout, rotation centers or outputs return
/// an error.
#[doc(hidden)]
pub fn compile_encoded_lookup_table<T, LM, M, F>(
    domain_len: usize,
    poly_length: usize,
    input_plaintext_modulus: T,
    lwe_modulus: LM,
    accumulator_modulus: M,
    encoded_output_at: F,
) -> Result<LookupTable<T>, LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
    F: Fn(usize) -> Result<T, LookupTableError>,
{
    validate_compilation(
        domain_len,
        poly_length,
        input_plaintext_modulus,
        lwe_modulus.explicit_value(),
    )?;
    let polynomial = compile_encoded_polynomial(
        domain_len,
        poly_length,
        1,
        input_plaintext_modulus,
        lwe_modulus,
        accumulator_modulus,
        |input, _| encoded_output_at(input),
    )?;
    Ok(LookupTable {
        polynomial,
        encoding: LookupTableEncoding {
            input_plaintext_modulus,
            input_ciphertext_modulus: lwe_modulus.explicit_value(),
            accumulator_modulus: accumulator_modulus.explicit_value(),
        },
    })
}

/// Compiles a validated input domain directly into the final interleaved polynomial.
/// Each nonempty interval uses its first row as the output-value buffer, then
/// copies that row to the remaining positions. No per-column storage is needed.
fn compile_encoded_polynomial<T, LM, M, F>(
    domain_len: usize,
    poly_length: usize,
    stride: usize,
    input_plaintext_modulus: T,
    lwe_modulus: LM,
    accumulator_modulus: M,
    encoded_output_at: F,
) -> Result<PolynomialOwned<T>, LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    let virtual_poly_length = poly_length / stride;
    let lwe_codec = RoundedCodec::new(input_plaintext_modulus, lwe_modulus);
    let quantizer = RotationQuantizer::new(lwe_modulus, virtual_poly_length * 2, 1);
    let rotation_center = |input| {
        // The validated front-half domain guarantees input <= D < t, so it fits T.
        let encoded = lwe_codec.encode_value(T::as_from(input), PlaintextEmbedding::Unsigned);
        quantizer.exponent(encoded)
    };
    let accumulator_value = accumulator_modulus.explicit_value();
    let mut polynomial = PolynomialOwned::zero(poly_length);
    let coefficients = polynomial.as_mut();

    // Centers use virtual positions; start/end index actual coefficients.
    let mut center = 0;
    let mut start = 0;
    for input in 0..domain_len {
        let mut next_center = rotation_center(input + 1);
        // For odd t, clamp the terminal center to the negacyclic image of
        // input zero at the virtual ring length; short prefixes keep their tail.
        if input + 1 == domain_len {
            next_center = next_center.min(virtual_poly_length);
        }
        if center >= next_center {
            return Err(LookupTableError::RotationCenterCollision {
                first_input: input,
                second_input: input + 1,
                exponent: next_center,
            });
        }
        let end = upper_midpoint(center, next_center) * stride;
        fill_input_interval(
            &mut coefficients[start..end],
            input,
            stride,
            accumulator_value,
            &encoded_output_at,
        )?;
        start = end;
        center = next_center;
    }
    fill_negated_tail(coefficients, start, stride, accumulator_modulus);
    Ok(polynomial)
}

/// Evaluates one encoded row and repeats it through a nonempty interval.
/// `row_len` is nonzero and divides the output length.
fn fill_input_interval<T, F>(
    output: &mut [T],
    input: usize,
    row_len: usize,
    accumulator_modulus: Option<T>,
    encoded_output_at: &F,
) -> Result<(), LookupTableError>
where
    T: FheUint,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    for (column, slot) in output[..row_len].iter_mut().enumerate() {
        let value = encoded_output_at(input, column)?;
        if accumulator_modulus.is_some_and(|q| value >= q) {
            return Err(LookupTableError::EncodedOutputOutOfRange { input });
        }
        *slot = value;
    }
    repeat_first_row(output, row_len);
    Ok(())
}

/// Fills the tail with -f(0), reusing the first programmed row.
/// The prefix contains at least one row; both parts contain whole rows.
#[inline]
fn fill_negated_tail<T: FheUint, M: RingContext<T>>(
    output: &mut [T],
    tail_start: usize,
    row_len: usize,
    modulus: M,
) {
    let (programmed, tail) = output.split_at_mut(tail_start);
    if tail.is_empty() {
        return;
    }
    for (slot, &first) in tail[..row_len].iter_mut().zip(&programmed[..row_len]) {
        *slot = modulus.reduce_neg(first);
    }
    repeat_first_row(tail, row_len);
}

/// Repeats the initialized first row through a whole number of rows.
/// `row_len` is nonzero and divides the nonempty output length.
#[inline]
fn repeat_first_row<T: Copy>(output: &mut [T], row_len: usize) {
    if row_len == 1 {
        output.fill(output[0]);
    } else {
        // Double the initialized prefix instead of copying each short row.
        let mut filled = row_len;
        while filled < output.len() {
            let (prefix, remaining) = output.split_at_mut(filled);
            let count = remaining.len().min(filled);
            remaining[..count].copy_from_slice(&prefix[..count]);
            filled += count;
        }
    }
}

/// Compiles encoded multi-output values into an interleaved negacyclic lookup
/// table.
///
/// The polynomial is split into `output_count` residue classes. Each class is
/// compiled as a lookup table of length `poly_length / output_count`. This is
/// the accumulator layout consumed by windowed modulus switching in
/// PBSManyLUT. Inherits [`compile_encoded_lookup_table`]'s encoding and output
/// contracts; `output_count` must be a non-zero power of two dividing `N`.
/// The front-half input domain must fit in `N / output_count` coefficients.
/// Outputs are evaluated once per pair, in input-major order. Callback errors
/// and noncanonical outputs stop compilation; no partial table is returned.
#[doc(hidden)]
pub fn compile_encoded_many_lookup_table<T, LM, M, F>(
    domain_len: usize,
    poly_length: usize,
    output_count: usize,
    input_plaintext_modulus: T,
    lwe_modulus: LM,
    accumulator_modulus: M,
    encoded_output_at: F,
) -> Result<ManyLookupTable<T>, LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    LM: ReduceAdd<T, Output = T> + PrepareModulusSwitch<ValueT = T>,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    validate_compilation(
        domain_len,
        poly_length,
        input_plaintext_modulus,
        lwe_modulus.explicit_value(),
    )?;
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

    let polynomial = compile_encoded_polynomial(
        domain_len,
        poly_length,
        output_count,
        input_plaintext_modulus,
        lwe_modulus,
        accumulator_modulus,
        encoded_output_at,
    )?;

    Ok(ManyLookupTable {
        polynomial,
        encoding: LookupTableEncoding {
            input_plaintext_modulus,
            input_ciphertext_modulus: lwe_modulus.explicit_value(),
            accumulator_modulus: accumulator_modulus.explicit_value(),
        },
        output_count,
    })
}

/// Validates the rotation layout before allocation or invoking the output function.
fn validate_compilation<T: FheUint>(
    domain_len: usize,
    poly_length: usize,
    input_plaintext_modulus: T,
    input_modulus: Option<T>,
) -> Result<(), LookupTableError> {
    poly_length
        .checked_mul(2)
        .filter(|&length| length.is_power_of_two() && T::try_from(length).is_ok())
        .ok_or(LookupTableError::InvalidPolynomialLength)?;
    if input_plaintext_modulus <= T::ONE
        || input_modulus.is_some_and(|q| q <= input_plaintext_modulus)
    {
        return Err(LookupTableError::InvalidInputEncoding);
    }
    let max_domain_len = lookup_table_domain_len(input_plaintext_modulus, poly_length)?;
    if domain_len == 0 || domain_len > max_domain_len {
        return Err(LookupTableError::InvalidInputDomain {
            domain_len,
            max_domain_len,
        });
    }
    Ok(())
}

/// Returns the integer midpoint of `lhs` and `rhs`, rounding upward.
#[inline]
fn upper_midpoint(lhs: usize, rhs: usize) -> usize {
    lhs.midpoint(rhs) + ((lhs ^ rhs) & 1)
}

/// An error produced while compiling a TFHE lookup table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LookupTableError {
    /// The polynomial length is not a non-zero power of two, or `2N` cannot
    /// be represented for modulus switching.
    #[error("invalid lookup-table polynomial length")]
    InvalidPolynomialLength,
    /// The rounded input encoding requires `t > 1` and explicit `q > t`.
    #[error("invalid lookup-table input encoding")]
    InvalidInputEncoding,
    /// The selected input domain must be a non-empty prefix of the front half.
    #[error("lookup-table input domain {domain_len} must belong to 1..={max_domain_len}")]
    InvalidInputDomain {
        /// Supplied domain length.
        domain_len: usize,
        /// Largest independently programmable domain length.
        max_domain_len: usize,
    },
    /// A raw output is not canonical under the accumulator modulus.
    #[error("encoded lookup-table output for input {input} is outside the accumulator modulus")]
    EncodedOutputOutOfRange {
        /// Input whose encoded output is invalid.
        input: usize,
    },
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
    /// Adjacent messages, or the last message and the negacyclic boundary,
    /// collide after encoding and modulus switching.
    #[error(
        "rotation-center collision between inputs {first_input} and {second_input} at exponent {exponent}"
    )]
    RotationCenterCollision {
        /// First adjacent plaintext input.
        first_input: usize,
        /// Second adjacent input, or the domain length at the negacyclic boundary.
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
