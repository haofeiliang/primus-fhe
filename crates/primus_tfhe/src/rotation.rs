//! Rotation quantization shared by LUT compilation and blind rotation.
//!
//! Compilation and execution use the same rounding and rotation-step rules.
//! These operations act on public ciphertext coefficients; the blind-rotation
//! key and algorithm determine how encrypted secret coefficients select rotations.
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

    /// Quantizes coefficients into an equally sized slice of rotation exponents.
    /// Fuses conversion to `usize`, rotation-step scaling and output writes with
    /// the prepared switch's batch operation, without intermediate allocation.
    ///
    /// # Correctness
    /// Every input coefficient must satisfy [`Self::exponent`]'s source range.
    ///
    /// # Panics
    /// Panics if the slices differ in length, before writing any output.
    #[inline]
    pub fn exponent_slice_to(&self, input: &[S::ValueT], output: &mut [usize]) {
        assert_eq!(
            input.len(),
            output.len(),
            "rotation exponent slice length mismatch"
        );
        self.switch
            .switch_map(input.iter().copied().zip(output), |value, out| {
                let exponent: usize = value.try_into().unwrap();
                *out = exponent * self.rotation_step;
            });
    }
}
