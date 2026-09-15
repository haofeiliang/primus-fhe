use primus_integer::FheUint;
use primus_reduce::Modulus;

#[inline]
pub(super) fn centered_half<T: FheUint>(t: T) -> T {
    (t >> 1u32) + (t & T::ONE)
}

/// Returns the magnitude and negative flag of the centered lift.
///
/// # Correctness
///
/// Requires `t >= 2`, `message < t`, and `half = ceil(t/2)`. A negative lift
/// then has strictly positive magnitude, including `1 -> -1` for `t = 2`.
#[inline]
pub(super) fn lift_centered_from_raw<T: FheUint>(message: T, t: T, half: T) -> (T, bool) {
    if message < half {
        (message, false)
    } else {
        (t - message, true)
    }
}

#[inline]
pub(super) fn check_message<T: FheUint>(message: T, t: T) {
    assert!(message < t, "message outside plaintext domain");
}

/// Checks the encoding-specific `q > t` constraint. Conversion preparation
/// validates the individual moduli.
pub(super) fn validate_moduli<T: FheUint, M: Modulus<ValueT = T>>(t: T, modulus: M) {
    assert!(
        modulus.explicit_value().is_none_or(|q| q > t),
        "ciphertext modulus must exceed plaintext modulus"
    );
}
