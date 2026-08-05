//! Low-level helpers shared by TFHE execution backends.

use primus_integer::FheUint;

/// Interprets a coefficient that is already an exponent in `[0, 2N)`.
#[inline]
pub fn direct_exponent<T: FheUint>(value: T, two_n: usize) -> usize {
    let exponent = value.try_into().unwrap();
    debug_assert!(exponent < two_n);
    exponent
}

/// Modulus-switches one LWE coefficient into an exponent in `[0, 2N)`.
#[inline]
pub fn modulus_switch<T: FheUint>(value: T, modulus: Option<T>, two_n: usize) -> usize {
    match modulus {
        Some(modulus) if T::try_from(two_n).ok() == Some(modulus) => direct_exponent(value, two_n),
        Some(modulus) => explicit_modulus_switch(value, modulus, two_n),
        None => native_modulus_switch(value, two_n),
    }
}

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

#[inline]
fn explicit_modulus_switch<T: FheUint>(value: T, modulus: T, two_n: usize) -> usize {
    debug_assert!(two_n.is_power_of_two());
    let target = T::try_from(two_n).unwrap();
    let (lo, hi) = value.carrying_mul(target, modulus >> 1u32);
    let rounded = T::div_wide(lo, hi, modulus);
    rounded.try_into().unwrap() & (two_n - 1)
}

#[cfg(test)]
mod tests {
    use super::{explicit_modulus_switch, native_modulus_switch};

    #[test]
    fn native_modulus_switch_rounds_half_up_and_wraps() {
        assert_eq!(native_modulus_switch(0u32, 8), 0);
        assert_eq!(native_modulus_switch(1u32 << 28, 8), 1);
        assert_eq!(native_modulus_switch((1u32 << 29) - 1, 8), 1);
        assert_eq!(native_modulus_switch(1u32 << 29, 8), 1);
        assert_eq!(native_modulus_switch(u32::MAX, 8), 0);
    }

    #[test]
    fn explicit_modulus_switch_matches_integer_oracle() {
        const Q: u32 = 132_120_577;
        for value in [0, 1, Q / 8, Q / 2, Q - 1] {
            let oracle = ((value as u64 * 8 + (Q / 2) as u64) / Q as u64) as usize & 7;
            assert_eq!(explicit_modulus_switch(value, Q, 8), oracle);
        }
    }
}
