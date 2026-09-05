//! Decomposition operators for fully homomorphic encryption.
//!
//! Approximate signed decomposition is a core building block for FHE schemes
//! such as FHEW/TFHE. This crate provides two flavors:
//!
//! - [`primitive`] — operates on single-limb values (`T: FheUint`).
//! - [`big_integer`] — operates on multi-limb [`BigUint`] values.
//!
//! [`BigUint`]: primus_integer::BigUint

#![deny(missing_docs)]

mod error;

pub use error::ApproxSignedBasisError;

/// Smallest supported base-2 logarithm of a decomposition basis.
pub const MIN_DECOMPOSITION_LOG_BASIS: u32 = 2;

/// Multi-limb decomposition operators and basis.
pub mod big_integer;
/// Single-limb (primitive) decomposition operators and basis.
pub mod primitive;

/// Selects the retained high levels and their first bit offset.
/// Callers have already validated `0 < log_basis <= value_bits`.
fn decomposition_length_and_drop_bits(
    value_bits: u32,
    log_basis: u32,
    reverse_length: Option<usize>,
) -> Result<(usize, u32), ApproxSignedBasisError> {
    let full_length = (value_bits / log_basis) as usize;
    let length = reverse_length.unwrap_or(full_length);
    if length == 0 {
        return Err(ApproxSignedBasisError::ZeroReverseLength);
    }
    if length > full_length {
        return Err(ApproxSignedBasisError::ReverseLengthTooLarge {
            reverse_length: length,
            full_length,
        });
    }
    Ok((length, value_bits - length as u32 * log_basis))
}
