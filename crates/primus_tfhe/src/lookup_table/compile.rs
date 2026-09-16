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
//! once for each crossing of `M`. For `k` outputs, `s = next_power_of_two(k)`;
//! lanes `k..s` are zero and only `0..k` are extracted.

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_poly::PolynomialOwned;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};

use crate::{LookupTableError, backend_support::RotationQuantizer};

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

/// Compiles a validated input domain directly into the final interleaved polynomial.
/// Each nonempty interval uses its first row as the output-value buffer, then
/// copies that row to the remaining positions. No per-column storage is needed.
pub(super) fn compile_encoded_polynomial<T, LM, M, F>(
    domain_len: usize,
    poly_length: usize,
    output_count: usize,
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
    let stride = output_count.next_power_of_two();
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
            output_count,
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
/// `0 < output_count <= row_len`; `row_len` divides the nonempty output length.
fn fill_input_interval<T, F>(
    output: &mut [T],
    input: usize,
    output_count: usize,
    row_len: usize,
    accumulator_modulus: Option<T>,
    encoded_output_at: &F,
) -> Result<(), LookupTableError>
where
    T: FheUint,
    F: Fn(usize, usize) -> Result<T, LookupTableError>,
{
    for (column, slot) in output[..output_count].iter_mut().enumerate() {
        let value = encoded_output_at(input, column)?;
        if accumulator_modulus.is_some_and(|q| value >= q) {
            return Err(LookupTableError::EncodedOutputOutOfRange { input });
        }
        *slot = value;
    }
    output[output_count..row_len].fill(T::ZERO);
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

/// Validates the rotation layout before allocation or invoking the output function.
pub(super) fn validate_compilation<T: FheUint>(
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
