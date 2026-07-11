use num_complex::Complex64;

use crate::{FftError, TorusFftValue};

/// Negacyclic FFT wrapper for polynomials modulo `X^N + 1`.
pub trait FftTable: Send + Sync {
    /// Creates a table for `N = 2^log_n` coefficients.
    fn new(log_n: u32) -> Result<Self, FftError>
    where
        Self: Sized;
    /// Returns the coefficient polynomial length `N`.
    fn poly_length(&self) -> usize;
    /// Returns the number of complex Fourier values, `N / 2`.
    fn fourier_length(&self) -> usize;
    /// Transforms torus coefficients, scaled by `2^-BITS`, to Fourier form.
    fn forward_as_torus<T: TorusFftValue>(&self, input: &[T], output: &mut [Complex64]);
    /// Transforms signed integer bit patterns without torus scaling.
    fn forward_as_integer<T: TorusFftValue>(&self, input: &[T], output: &mut [Complex64]);
    /// Transforms ordinary integer-valued floating point coefficients.
    fn forward_integer_f64(&self, input: &[f64], output: &mut [Complex64]);
    /// Converts Fourier form back to torus coefficients.
    fn backward_as_torus<T: TorusFftValue>(&self, input: &[Complex64], output: &mut [T]);
}
