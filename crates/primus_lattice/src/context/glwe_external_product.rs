use primus_data::DataMut;
use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use crate::{
    GadgetSize,
    glwe::{FourierGlwe, NttGlwe},
};

/// Pre-allocated scratch buffers for a native-torus Fourier external product.
///
/// All allocations and contract checks happen when the context is constructed
/// or resized. The external-product hot path only mutates its internal buffers.
///
/// The bound [`GadgetSize`] includes the mask and body polynomial counts plus
/// the decomposition length. Each operation overwrites every internal buffer.
pub struct FourierExternalProductContext<T: TorusFftValue> {
    size: GadgetSize,
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub(crate) carries: Vec<bool>,
    /// Decomposed (signed) digits for one polynomial (length = `poly_length`).
    pub(crate) decomposed_poly: Vec<T>,
    /// FFT of the decomposed polynomial (length = `fourier_length`).
    pub(crate) decomposed_fourier: Vec<Complex64>,
    /// Accumulator in Fourier domain.
    pub(crate) fourier_accumulator: FourierGlwe<Vec<Complex64>>,
}

impl<T: TorusFftValue> FourierExternalProductContext<T> {
    /// Creates a new context with all buffers pre-allocated.
    ///
    /// The accumulator is sized for all mask polynomials and the body.
    pub fn new(size: GadgetSize) -> Self {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();
        let fourier_length = glwe_size.fourier_poly_len();

        Self {
            size,
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: vec![Complex64::default(); fourier_length],
            fourier_accumulator: FourierGlwe(vec![
                Complex64::default();
                glwe_size.fourier_glwe_len()
            ]),
        }
    }

    /// Rebinds the context to another decomposition layout without reallocating.
    ///
    /// # Panics
    ///
    /// Panics if `size` has a different GLWE dimension or polynomial length.
    pub fn rebind(&mut self, size: GadgetSize) {
        assert_eq!(
            self.size.glwe_size(),
            size.glwe_size(),
            "cannot rebind Fourier external-product context to a different GLWE layout"
        );
        self.size = size;
    }

    /// Rebinds the context and resizes its scratch buffers when the GLWE layout changes.
    pub fn resize(&mut self, size: GadgetSize) {
        if self.size.glwe_size() == size.glwe_size() {
            self.size = size;
            return;
        }

        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();
        let fourier_length = glwe_size.fourier_poly_len();

        self.size = size;
        self.carries.resize(poly_length, false);
        self.decomposed_poly.resize(poly_length, T::ZERO);
        self.decomposed_fourier
            .resize(fourier_length, Complex64::default());
        self.fourier_accumulator
            .0
            .resize(glwe_size.fourier_glwe_len(), Complex64::default());
    }

    /// Returns the bound external-product layout.
    #[must_use]
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }
}

/// Pre-allocated scratch buffers for an NTT external product.
///
/// The bound [`GadgetSize`] includes the mask and body polynomial counts plus
/// the decomposition length. Each operation overwrites every internal buffer.
pub struct NttExternalProductContext<T: FheUint> {
    size: GadgetSize,
    /// Adjusted coefficients used by decomposition (length = `poly_length`).
    pub(crate) adjusted_poly: Vec<T>,
    /// Carry bits, one per coefficient (length = `poly_length`).
    pub(crate) carries: Vec<bool>,
    /// One decomposed polynomial, transformed in place to NTT form.
    pub(crate) decomposed_ntt: Vec<T>,
    /// Accumulator in NTT form.
    pub(crate) ntt_accumulator: NttGlwe<Vec<T>>,
}

/// Mutable view of the buffers used by an NTT external product.
///
/// The accumulator may borrow either the context-owned buffer or a
/// caller-provided NTT GLWE output.
pub(crate) struct NttExternalProductContextRefMut<'a, T: FheUint> {
    size: GadgetSize,
    /// Adjusted coefficients used by decomposition.
    pub(crate) adjusted_poly: &'a mut [T],
    /// Carry bits used by decomposition.
    pub(crate) carries: &'a mut [bool],
    /// One decomposed polynomial, transformed in place to NTT form.
    pub(crate) decomposed_ntt: &'a mut [T],
    /// Accumulator selected for this external product.
    pub(crate) ntt_accumulator: NttGlwe<&'a mut [T]>,
}

impl<T: FheUint> NttExternalProductContextRefMut<'_, T> {
    /// Returns the external-product layout bound to this view.
    #[must_use]
    #[inline]
    pub(crate) fn size(&self) -> GadgetSize {
        self.size
    }
}

impl<T: FheUint> NttExternalProductContext<T> {
    /// Creates a context with all buffers pre-allocated.
    pub fn new(size: GadgetSize) -> Self {
        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();

        Self {
            size,
            adjusted_poly: vec![T::ZERO; poly_length],
            carries: vec![false; poly_length],
            decomposed_ntt: vec![T::ZERO; poly_length],
            ntt_accumulator: NttGlwe::zero(glwe_size.glwe_len()),
        }
    }

    /// Rebinds the context to another decomposition layout without reallocating.
    ///
    /// # Panics
    ///
    /// Panics if `size` has a different GLWE dimension or polynomial length.
    pub fn rebind(&mut self, size: GadgetSize) {
        assert_eq!(
            self.size.glwe_size(),
            size.glwe_size(),
            "cannot rebind NTT external-product context to a different GLWE layout"
        );
        self.size = size;
    }

    /// Rebinds the context and resizes its scratch buffers when the GLWE layout changes.
    pub fn resize(&mut self, size: GadgetSize) {
        if self.size.glwe_size() == size.glwe_size() {
            self.size = size;
            return;
        }

        let glwe_size = size.glwe_size();
        let poly_length = glwe_size.poly_length();

        self.size = size;
        self.adjusted_poly.resize(poly_length, T::ZERO);
        self.carries.resize(poly_length, false);
        self.decomposed_ntt.resize(poly_length, T::ZERO);
        self.ntt_accumulator.0.resize(glwe_size.glwe_len(), T::ZERO);
    }

    /// Returns the bound external-product layout.
    #[must_use]
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Borrows all scratch buffers and the context-owned accumulator.
    #[inline]
    pub(crate) fn as_mut(&mut self) -> NttExternalProductContextRefMut<'_, T> {
        NttExternalProductContextRefMut {
            size: self.size,
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttGlwe(self.ntt_accumulator.as_mut()),
        }
    }

    /// Borrows the scratch buffers while using `accumulator` as the output.
    #[inline]
    pub(crate) fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut NttGlwe<S>,
    ) -> NttExternalProductContextRefMut<'a, T>
    where
        S: DataMut<Elem = T>,
    {
        NttExternalProductContextRefMut {
            size: self.size,
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttGlwe(accumulator.as_mut()),
        }
    }
}
