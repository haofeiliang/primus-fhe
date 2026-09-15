//! Low-level helpers shared by TFHE execution backends.
//!
//! For canonical `x` modulo `q`, rotation quantization is
//! `R(x, q, L) = floor((x * L + floor(q / 2)) / q) mod L`.
//! Ties round upward, including the wrap from `L` to zero; `None` means
//! `q = 2^T::BITS`. With stride `s`, let `R_s(x) = s * R(x, q, 2N/s)`.
//! Backends rotate the LUT by
//! `-R_s(b) + sum(R_s(a[i]) * secret[i])`, quantizing each LWE coefficient
//! separately. Quantizing the decrypted phase once is not equivalent.

use primus_integer::FheUint;

/// Interprets a coefficient that is already an exponent in `[0, 2N)`.
#[inline]
pub fn direct_exponent<T: FheUint>(value: T, two_n: usize) -> usize {
    let exponent = value.try_into().unwrap();
    debug_assert!(exponent < two_n);
    exponent
}

/// Modulus-switches one LWE coefficient into an exponent in `[0, 2N)`.
///
/// # Correctness
///
/// `two_n` must be a power of two at least two. With an explicit nonzero
/// modulus, `value` must be canonical and `two_n` must fit in `T`.
/// With the native modulus, `log2(two_n)` must not exceed `T::BITS`.
#[inline]
pub fn modulus_switch<T: FheUint>(value: T, modulus: Option<T>, two_n: usize) -> usize {
    match modulus {
        Some(modulus) if T::try_from(two_n).ok() == Some(modulus) => direct_exponent(value, two_n),
        Some(modulus) => explicit_modulus_switch(value, modulus, two_n),
        None => native_modulus_switch(value, two_n),
    }
}

/// Modulus-switches one LWE coefficient to a multiple of `window` in
/// `[0, 2N)`.
///
/// Computes `window * R(value, q, two_n / window)`: rounding happens in the
/// smaller rotation domain, before scaling. Clearing low bits after ordinary
/// modulus switching is not equivalent. Multiples of `window` preserve the
/// residue classes of an interleaved PBSManyLUT accumulator.
///
/// # Correctness
///
/// Inherits [`modulus_switch`]'s coefficient requirements. `two_n` must be a
/// power of two; `window` must be a power of two in `1..=two_n / 2`, leaving
/// at least two virtual rotation positions. `two_n / window` must satisfy
/// [`modulus_switch`]'s target-width requirements.
#[inline]
pub fn windowed_modulus_switch<T: FheUint>(
    value: T,
    modulus: Option<T>,
    two_n: usize,
    window: usize,
) -> usize {
    debug_assert!(window.is_power_of_two());
    debug_assert!(window < two_n && two_n.is_multiple_of(window));
    modulus_switch(value, modulus, two_n / window) * window
}

/// Rounds a native-torus coefficient into the rotation domain.
#[inline]
fn native_modulus_switch<T: FheUint>(value: T, two_n: usize) -> usize {
    debug_assert!(two_n.is_power_of_two());
    let target_log = two_n.trailing_zeros();
    assert!(target_log <= T::BITS);
    let shift = T::BITS - target_log;
    let rounded = if shift == 0 {
        value
    } else {
        value.wrapping_add(T::ONE << (shift - 1)) >> shift
    };
    rounded.try_into().unwrap() & (two_n - 1)
}

/// Rounds an explicitly reduced coefficient into the rotation domain.
#[inline]
fn explicit_modulus_switch<T: FheUint>(value: T, modulus: T, two_n: usize) -> usize {
    debug_assert!(two_n.is_power_of_two());
    let target = T::try_from(two_n).unwrap();
    let (lo, hi) = value.carrying_mul(target, modulus >> 1u32);
    let rounded = T::div_wide(lo, hi, modulus);
    rounded.try_into().unwrap() & (two_n - 1)
}
