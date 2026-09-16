//! Low-level helpers shared by TFHE execution backends.
//!
//! For canonical `x` modulo `q`, rotation quantization is
//! `R(x, q, L) = floor((x * L + floor(q / 2)) / q) mod L`.
//! Ties round upward, including the wrap from `L` to zero; `NativeModulus<T>` uses
//! `q = 2^T::BITS`. With rotation step `s`, let `R_s(x) = s * R(x, q, 2N/s)`.
//! Backends rotate the LUT by
//! `-R_s(b) + sum(R_s(a[i]) * secret[i])`, quantizing each LWE coefficient
//! separately. Quantizing the decrypted phase once is not equivalent.

use primus_integer::FheUint;
use primus_modulus::PowOf2Modulus;
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
    rotation_step: usize,
}

impl<S: PreparedModulusSwitch> RotationQuantizer<S> {
    /// Prepares `rotation_step * R(value, q, two_n/rotation_step)`.
    /// Rounding in the smaller domain preserves interleaved LUT residue classes.
    /// Execution uses `two_n = 2N` and the LUT's padded output count `s` as the
    /// step. Compilation uses `two_n = 2N/s` and step one to obtain centers in
    /// per-output coefficient coordinates.
    ///
    /// # Panics
    /// Panics unless `two_n >= 2` and `rotation_step` are powers of two,
    /// `rotation_step <= two_n/2`, and `two_n` is representable by `T`.
    #[must_use]
    pub fn new<T, M>(modulus: M, two_n: usize, rotation_step: usize) -> Self
    where
        T: FheUint,
        M: PrepareModulusSwitch<ValueT = T, Prepared = S>,
    {
        assert!(
            two_n >= 2 && two_n.is_power_of_two(),
            "invalid rotation domain"
        );
        assert!(
            rotation_step.is_power_of_two() && rotation_step <= two_n / 2,
            "invalid rotation step"
        );
        let rotation_domain =
            T::try_from(two_n).expect("rotation domain must fit the input coefficient type");
        let target = rotation_domain >> rotation_step.trailing_zeros();
        let switch = modulus.prepare_switch_to(PowOf2Modulus::new(target));
        Self {
            switch,
            rotation_step,
        }
    }

    /// Quantizes one canonical input coefficient into `[0,two_n)`.
    ///
    /// # Correctness
    /// `value` must be canonical under the input modulus used at construction.
    #[must_use]
    #[inline]
    pub fn exponent(&self, value: S::ValueT) -> usize {
        let exponent: usize = self.switch.switch(value).try_into().unwrap();
        exponent * self.rotation_step
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

/// Computes `rotation_step * R(value,q,two_n/rotation_step)`.
/// Clearing low bits after ordinary switching is not equivalent.
/// Inherits [`RotationQuantizer`]'s contracts.
#[must_use]
#[inline]
pub fn modulus_switch_with_step<T, M>(
    value: T,
    modulus: M,
    two_n: usize,
    rotation_step: usize,
) -> usize
where
    T: FheUint,
    M: PrepareModulusSwitch<ValueT = T>,
{
    RotationQuantizer::new(modulus, two_n, rotation_step).exponent(value)
}
