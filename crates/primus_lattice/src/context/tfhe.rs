use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use crate::glwe::{FourierGlwe, NttGlwe};

/// Precomputed coefficient-domain GLWE layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlweSize {
    poly_length: usize,
    glwe_dimension: usize,
    glwe_len: usize,
}

impl GlweSize {
    /// Creates and validates a GLWE layout.
    pub fn new(poly_length: usize, glwe_dimension: usize) -> Self {
        assert!(poly_length >= 2);
        assert!(poly_length.is_power_of_two());
        let component_count = glwe_dimension
            .checked_add(1)
            .expect("GLWE component count overflow");
        let glwe_len = component_count
            .checked_mul(poly_length)
            .expect("GLWE length overflow");
        Self {
            poly_length,
            glwe_dimension,
            glwe_len,
        }
    }

    /// Returns the polynomial length.
    #[inline]
    pub fn poly_length(self) -> usize {
        self.poly_length
    }

    /// Returns the GLWE dimension (the number of mask polynomials).
    #[inline]
    pub fn glwe_dimension(self) -> usize {
        self.glwe_dimension
    }

    /// Returns the number of GLWE components, including the body.
    #[inline]
    pub fn component_count(self) -> usize {
        self.glwe_dimension + 1
    }

    /// Returns the coefficient-domain GLWE length.
    #[inline]
    pub fn glwe_len(self) -> usize {
        self.glwe_len
    }

    /// Returns the Fourier GLWE length.
    #[inline]
    pub fn fourier_glwe_len(self) -> usize {
        self.glwe_len / 2
    }
}

/// Pre-allocated scratch buffers for the TFHE external product.
///
/// All allocations and contract checks happen when the context is constructed
/// or resized. The external-product hot path only mutates its internal buffers.
///
/// # GLWE dimension convention
///
/// `glwe_dimension` is the count of *mask* polynomials (`k`). The
/// accumulator is sized for `glwe_dimension + 1` polynomials (k mask + 1 body).
pub struct TfheFftContext<T: TorusFftValue> {
    size: GlweSize,
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub(crate) carries: Vec<bool>,
    /// Decomposed (signed) digits for one polynomial (length = `poly_length`).
    pub(crate) decomposed_poly: Vec<T>,
    /// FFT of the decomposed polynomial (length = `fourier_length`).
    pub(crate) decomposed_fourier: Vec<Complex64>,
    /// Accumulator in Fourier domain.
    pub(crate) fourier_accumulator: FourierGlwe<Vec<Complex64>>,
}

impl<T: TorusFftValue> TfheFftContext<T> {
    /// Creates a new context with all buffers pre-allocated.
    ///
    /// `glwe_dimension` is the mask count `k`; the accumulator is sized for
    /// `k + 1` polynomials.
    pub fn new(glwe_dimension: usize, poly_length: usize) -> Self {
        let fourier_length = poly_length / 2;
        let size = GlweSize::new(poly_length, glwe_dimension);

        Self {
            size,
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: vec![Complex64::default(); fourier_length],
            fourier_accumulator: FourierGlwe(vec![Complex64::default(); size.fourier_glwe_len()]),
        }
    }

    /// Rebinds the context and resizes its scratch buffers.
    pub fn resize(&mut self, glwe_dimension: usize, poly_length: usize) {
        let fourier_length = poly_length / 2;
        let size = GlweSize::new(poly_length, glwe_dimension);

        self.size = size;
        self.carries.resize(poly_length, false);
        self.decomposed_poly.resize(poly_length, T::ZERO);
        self.decomposed_fourier
            .resize(fourier_length, Complex64::default());
        self.fourier_accumulator
            .0
            .resize(size.fourier_glwe_len(), Complex64::default());
    }

    /// Returns the bound external-product layout.
    #[inline]
    pub fn size(&self) -> GlweSize {
        self.size
    }
}

/// Pre-allocated scratch buffers for the NTT TFHE external product.
///
/// `glwe_dimension` is the number of mask polynomials. The accumulator holds
/// `glwe_dimension + 1` NTT polynomials, including the body.
pub struct TfheNttContext<T: FheUint> {
    size: GlweSize,
    /// Adjusted coefficients used by decomposition (length = `poly_length`).
    pub(crate) adjusted_poly: Vec<T>,
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub(crate) carries: Vec<bool>,
    /// One decomposed polynomial, transformed in place to NTT form.
    pub(crate) decomposed_ntt: Vec<T>,
    /// Accumulator in NTT form.
    pub(crate) ntt_accumulator: NttGlwe<Vec<T>>,
}

impl<T: FheUint> TfheNttContext<T> {
    /// Creates a context with all buffers pre-allocated.
    pub fn new(glwe_dimension: usize, poly_length: usize) -> Self {
        let size = GlweSize::new(poly_length, glwe_dimension);

        Self {
            size,
            adjusted_poly: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            decomposed_ntt: vec![T::ZERO; poly_length],
            ntt_accumulator: NttGlwe::zero(size.glwe_len()),
        }
    }

    /// Rebinds the context and resizes its scratch buffers.
    pub fn resize(&mut self, glwe_dimension: usize, poly_length: usize) {
        let size = GlweSize::new(poly_length, glwe_dimension);

        self.size = size;
        self.adjusted_poly.resize(poly_length, T::ZERO);
        self.carries.resize(poly_length, false);
        self.decomposed_ntt.resize(poly_length, T::ZERO);
        self.ntt_accumulator.0.resize(size.glwe_len(), T::ZERO);
    }

    /// Returns the bound external-product layout.
    #[inline]
    pub fn size(&self) -> GlweSize {
        self.size
    }
}
