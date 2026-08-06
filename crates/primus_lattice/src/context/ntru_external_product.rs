use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use crate::ntru::{FourierNtru, NttNtru};

/// Pre-allocated scratch buffers for a native-torus Fourier NGSW external product.
pub struct FourierNtruExternalProductContext<T: TorusFftValue> {
    poly_length: usize,
    /// Carry bits reused while decomposing one coefficient polynomial.
    pub(crate) carries: Vec<bool>,
    /// Coefficient-domain digits produced for one decomposition level.
    pub(crate) decomposed_poly: Vec<T>,
    /// Fourier transform of `decomposed_poly`.
    pub(crate) decomposed_fourier: Vec<Complex64>,
    /// Transform-domain sum of the current external products.
    pub(crate) fourier_accumulator: FourierNtru<Vec<Complex64>>,
}

impl<T: TorusFftValue> FourierNtruExternalProductContext<T> {
    /// Creates reusable buffers for NTRU polynomials of length `poly_length`.
    #[inline]
    pub fn new(poly_length: usize) -> Self {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        let fourier_length = poly_length / 2;
        Self {
            poly_length,
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: vec![Complex64::default(); fourier_length],
            fourier_accumulator: FourierNtru::zero(fourier_length),
        }
    }

    /// Returns the coefficient polynomial length bound to this context.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }
}

/// Pre-allocated scratch buffers for an exact NTT NGSW external product.
pub struct NttNtruExternalProductContext<T: FheUint> {
    poly_length: usize,
    /// Modulus-adjusted coefficients reused as decomposition input.
    pub(crate) adjusted_poly: Vec<T>,
    /// Carry bits reused while decomposing `adjusted_poly`.
    pub(crate) carries: Vec<bool>,
    /// Digits for one decomposition level, transformed in place to NTT form.
    pub(crate) decomposed_ntt: Vec<T>,
    /// Transform-domain sum of the current external products.
    pub(crate) ntt_accumulator: NttNtru<Vec<T>>,
}

impl<T: FheUint> NttNtruExternalProductContext<T> {
    /// Creates reusable buffers for NTRU polynomials of length `poly_length`.
    #[inline]
    pub fn new(poly_length: usize) -> Self {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        Self {
            poly_length,
            adjusted_poly: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            decomposed_ntt: vec![T::ZERO; poly_length],
            ntt_accumulator: NttNtru::zero(poly_length),
        }
    }

    /// Returns the coefficient polynomial length bound to this context.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }
}
