use aligned_vec::{AVec, avec};
use primus_data::DataMut;
use primus_fft::{Complex64, TorusFftValue};
use primus_integer::FheUint;

use crate::ntru::{FourierNtru, NttNtru};

/// Pre-allocated scratch buffers for native-torus Fourier NTRU gadget products.
/// Owned Fourier buffers use cache-line alignment for repeated FFT and product passes.
///
/// Shared by NLev key switching and NGSW external products, including CMUX.
///
/// # Correctness
///
/// Scratch lengths are fixed by `poly_length`; decomposition levels are not
/// bound, so the workspace can be reused across different decomposition lengths.
/// Callers must supply compatible input and gadget layouts and matching transform
/// lengths. The basis and transform table are not stored in this context.
///
/// Overwriting products initialize the accumulator; internal accumulating
/// products require an initialized accumulator. Other scratch is written before
/// use, and no manual reset is needed between operations.
/// Fourier data must use a compatible FFT layout, and the basis must use the
/// implicit native-torus modulus.
pub struct FourierNtruExternalProductContext<T: TorusFftValue> {
    poly_length: usize,
    /// Carry bits reused while decomposing one coefficient polynomial.
    carries: Vec<bool>,
    /// Coefficient-domain digits produced for one decomposition level.
    decomposed_poly: Vec<T>,
    /// Fourier transform of `decomposed_poly`.
    decomposed_fourier: AVec<Complex64>,
    /// Transform-domain sum of the current external products.
    fourier_accumulator: FourierNtru<AVec<Complex64>>,
}

/// Mutable view selecting either the context-owned or caller-provided Fourier accumulator.
/// Decomposition scratch remains borrowed from the owning context.
pub(crate) struct FourierNtruExternalProductContextRefMut<'a, T: TorusFftValue> {
    poly_length: usize,
    pub(crate) carries: &'a mut [bool],
    pub(crate) decomposed_poly: &'a mut [T],
    pub(crate) decomposed_fourier: &'a mut [Complex64],
    pub(crate) fourier_accumulator: FourierNtru<&'a mut [Complex64]>,
}

impl<T: TorusFftValue> FourierNtruExternalProductContextRefMut<'_, T> {
    #[must_use]
    #[inline]
    pub(crate) fn poly_length(&self) -> usize {
        self.poly_length
    }
}

impl<T: TorusFftValue> FourierNtruExternalProductContext<T> {
    /// Creates reusable buffers for NTRU polynomials of length `poly_length`.
    ///
    /// # Correctness
    ///
    /// `poly_length` must be a power of two of at least two, supported by the
    /// transform table used by subsequent operations. This is only
    /// debug-asserted here; construction does not bind or validate a table.
    #[inline]
    #[must_use]
    pub fn new(poly_length: usize) -> Self {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        let fourier_length = poly_length / 2;
        Self {
            poly_length,
            carries: vec![false; poly_length],
            decomposed_poly: vec![T::ZERO; poly_length],
            decomposed_fourier: avec![Complex64::default(); fourier_length],
            fourier_accumulator: FourierNtru(avec![Complex64::default(); fourier_length]),
        }
    }

    /// Returns the coefficient polynomial length bound to this context.
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Borrows decomposition scratch and the context-owned accumulator.
    #[inline]
    pub(crate) fn as_mut(&mut self) -> FourierNtruExternalProductContextRefMut<'_, T> {
        FourierNtruExternalProductContextRefMut {
            poly_length: self.poly_length,
            carries: &mut self.carries,
            decomposed_poly: &mut self.decomposed_poly,
            decomposed_fourier: &mut self.decomposed_fourier,
            fourier_accumulator: FourierNtru(self.fourier_accumulator.as_mut()),
        }
    }

    /// Borrows scratch while accumulating directly into `accumulator`.
    /// The operation boundary must establish the output's transform length.
    #[inline]
    pub(crate) fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut FourierNtru<S>,
    ) -> FourierNtruExternalProductContextRefMut<'a, T>
    where
        S: DataMut<Elem = Complex64>,
    {
        FourierNtruExternalProductContextRefMut {
            poly_length: self.poly_length,
            carries: &mut self.carries,
            decomposed_poly: &mut self.decomposed_poly,
            decomposed_fourier: &mut self.decomposed_fourier,
            fourier_accumulator: FourierNtru(accumulator.as_mut()),
        }
    }
}

/// Pre-allocated scratch buffers for exact NTT NTRU gadget products.
///
/// Shared by NLev key switching and NGSW external products, including CMUX.
///
/// # Correctness
///
/// Scratch lengths are fixed by `poly_length`; decomposition levels are not
/// bound, so the workspace can be reused across different decomposition lengths.
/// Callers must supply compatible input and gadget layouts and matching transform
/// lengths. The basis and transform table are not stored in this context.
///
/// Overwriting products initialize the accumulator; internal accumulating
/// products require an initialized accumulator. Other scratch is written before
/// use, and no manual reset is needed between operations.
/// The basis, NTT table, and modular arithmetic must use the same modulus.
pub struct NttNtruExternalProductContext<T: FheUint> {
    poly_length: usize,
    /// Modulus-adjusted coefficients reused as decomposition input.
    adjusted_poly: Vec<T>,
    /// Carry bits reused while decomposing `adjusted_poly`.
    carries: Vec<bool>,
    /// Digits for one decomposition level, transformed in place to NTT form.
    decomposed_ntt: Vec<T>,
    /// Transform-domain sum of the current external products.
    ntt_accumulator: NttNtru<Vec<T>>,
}

/// Mutable view selecting either the context-owned or caller-provided NTT accumulator.
/// Decomposition scratch remains borrowed from the owning context.
pub(crate) struct NttNtruExternalProductContextRefMut<'a, T: FheUint> {
    poly_length: usize,
    pub(crate) adjusted_poly: &'a mut [T],
    pub(crate) carries: &'a mut [bool],
    pub(crate) decomposed_ntt: &'a mut [T],
    pub(crate) ntt_accumulator: NttNtru<&'a mut [T]>,
}

impl<T: FheUint> NttNtruExternalProductContextRefMut<'_, T> {
    #[must_use]
    #[inline]
    pub(crate) fn poly_length(&self) -> usize {
        self.poly_length
    }
}

impl<T: FheUint> NttNtruExternalProductContext<T> {
    /// Creates reusable buffers for NTRU polynomials of length `poly_length`.
    ///
    /// # Correctness
    ///
    /// `poly_length` must be a power of two of at least two, supported by the
    /// transform table used by subsequent operations. This is only
    /// debug-asserted here; construction does not bind or validate a table.
    #[inline]
    #[must_use]
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

    /// Borrows decomposition scratch and the context-owned accumulator.
    #[inline]
    pub(crate) fn as_mut(&mut self) -> NttNtruExternalProductContextRefMut<'_, T> {
        NttNtruExternalProductContextRefMut {
            poly_length: self.poly_length,
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttNtru(self.ntt_accumulator.as_mut()),
        }
    }

    /// Borrows scratch while accumulating directly into `accumulator`.
    /// The operation boundary must establish the output's transform length.
    #[inline]
    pub(crate) fn as_mut_with_accumulator<'a, S>(
        &'a mut self,
        accumulator: &'a mut NttNtru<S>,
    ) -> NttNtruExternalProductContextRefMut<'a, T>
    where
        S: DataMut<Elem = T>,
    {
        NttNtruExternalProductContextRefMut {
            poly_length: self.poly_length,
            adjusted_poly: &mut self.adjusted_poly,
            carries: &mut self.carries,
            decomposed_ntt: &mut self.decomposed_ntt,
            ntt_accumulator: NttNtru(accumulator.as_mut()),
        }
    }
}
