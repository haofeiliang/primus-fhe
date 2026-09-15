//! Low-level helpers shared by TFHE execution backends.
//!
//! For canonical `x` modulo `q`, rotation quantization is
//! `R(x, q, L) = floor((x * L + floor(q / 2)) / q) mod L`.
//! Ties round upward, including the wrap from `L` to zero; `NativeModulus<T>` uses
//! `q = 2^T::BITS`. With stride `s`, let `R_s(x) = s * R(x, q, 2N/s)`.
//! Backends rotate the LUT by
//! `-R_s(b) + sum(R_s(a[i]) * secret[i])`, quantizing each LWE coefficient
//! separately. Quantizing the decrypted phase once is not equivalent.

use primus_integer::FheUint;
use primus_modulus::{NativeModulus, PowOf2Modulus};
use primus_reduce::{PrepareModulusSwitch, PreparedModulusSwitch};

/// Interprets a coefficient that is already an exponent in `[0, 2N)`.
#[inline]
pub fn direct_exponent<T: FheUint>(value: T, two_n: usize) -> usize {
    let exponent = value.try_into().unwrap();
    debug_assert!(exponent < two_n);
    exponent
}

/// Prepared coefficient quantization for ordinary and interleaved PBS.
/// The input modulus and target width are fixed before processing coefficients.
#[derive(Clone, Copy, Debug)]
pub struct RotationQuantizer<S: PreparedModulusSwitch> {
    switch: S,
    window: usize,
}

impl<S: PreparedModulusSwitch> RotationQuantizer<S> {
    /// Prepares `window * R(value, q, two_n/window)`.
    /// Rounding in the smaller domain preserves interleaved LUT residue classes.
    ///
    /// # Panics
    /// Panics unless `two_n >= 2` and `window` are powers of two,
    /// `window <= two_n/2`, and `log2(two_n/window) <= T::BITS`.
    #[must_use]
    pub fn new<T, M>(modulus: M, two_n: usize, window: usize) -> Self
    where
        T: FheUint,
        M: PrepareModulusSwitch<ValueT = T, Prepared = S>,
    {
        assert!(
            two_n >= 2 && two_n.is_power_of_two(),
            "invalid rotation domain"
        );
        assert!(
            window.is_power_of_two() && window <= two_n / 2,
            "invalid rotation window"
        );
        let target_log = (two_n / window).trailing_zeros();
        assert!(target_log <= T::BITS, "invalid modulus-switch target width");
        let switch = if target_log == T::BITS {
            modulus.prepare_switch_to(NativeModulus::new())
        } else {
            modulus.prepare_switch_to(PowOf2Modulus::new(T::ONE << target_log))
        };
        Self { switch, window }
    }

    /// Quantizes one canonical input coefficient into `[0,two_n)`.
    ///
    /// # Correctness
    /// `value` must be canonical under the input modulus used at construction.
    #[must_use]
    #[inline]
    pub fn exponent(&self, value: S::ValueT) -> usize {
        let exponent: usize = self.switch.switch(value).try_into().unwrap();
        exponent * self.window
    }
}

/// Modulus-switches one canonical coefficient into `[0,two_n)`.
/// For repeated coefficients, reuse [`RotationQuantizer`]. Its construction
/// requirements and coefficient correctness contract apply.
#[must_use]
#[inline]
pub fn modulus_switch<T, M>(value: T, modulus: M, two_n: usize) -> usize
where
    T: FheUint,
    M: PrepareModulusSwitch<ValueT = T>,
{
    RotationQuantizer::new(modulus, two_n, 1).exponent(value)
}

/// Computes `window * R(value,q,two_n/window)`; clearing low bits after ordinary
/// switching is not equivalent. Inherits [`RotationQuantizer`]'s contracts.
#[must_use]
#[inline]
pub fn windowed_modulus_switch<T, M>(value: T, modulus: M, two_n: usize, window: usize) -> usize
where
    T: FheUint,
    M: PrepareModulusSwitch<ValueT = T>,
{
    RotationQuantizer::new(modulus, two_n, window).exponent(value)
}
