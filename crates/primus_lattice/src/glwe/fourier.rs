use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};

use primus_poly::{FourierPolynomial, FourierPolynomialIter, FourierPolynomialIterMut};

/// Fourier-domain GLWE ciphertext.
///
/// ## Layout
///
/// ```text
/// |--a1--| ... |--ak--|--b--|
/// ```
///
/// Each component contains `fourier_length` complex values.
/// Total data length: `(k + 1) * fourier_length` complex values.
#[derive(Clone)]
pub struct FourierGlwe<S>(pub S)
where
    S: RawData<Elem = Complex64>;

impl_fourier_iters!(FourierGlwe);
impl_fourier_core!(FourierGlwe);
impl_fourier_iter_sub!(
    FourierGlwe,
    FourierPolynomial,
    FourierPolynomialIter,
    FourierPolynomialIterMut,
    fourier_poly
);

// ---------------------------------------------------------------------------
// GLWE-specific methods
// ---------------------------------------------------------------------------

impl<S> FourierGlwe<S>
where
    S: RawData<Elem = Complex64> + Data,
{
    /// Returns the `a` components and `b` component as immutable slices.
    ///
    /// `mid = k * fourier_length` splits the mask from the body.
    /// `mid` must be `<= self.0.len()`.
    #[inline]
    pub fn a_b_slices(&self, mid: usize) -> (&[Complex64], &[Complex64]) {
        self.0.split_at(mid)
    }
}

impl<S> FourierGlwe<S>
where
    S: RawData<Elem = Complex64> + DataMut,
{
    /// Returns the `a` components and `b` component as mutable slices.
    #[inline]
    pub fn a_b_mut_slices(&mut self, mid: usize) -> (&mut [Complex64], &mut [Complex64]) {
        self.0.split_at_mut(mid)
    }

    /// Performs `self += poly * rhs` for each component (pointwise FMA).
    ///
    /// This is the core operation in the TFHE external product hot loop:
    /// the accumulator GLWE accumulates the product of a decomposed FFT
    /// polynomial with a GGSW key GLWE.
    #[inline]
    pub fn add_mul_fourier_poly_assign<A, B>(
        &mut self,
        poly: &FourierPolynomial<A>,
        rhs: &FourierGlwe<B>,
    ) where
        A: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = Complex64> + Data,
    {
        let fourier_length = poly.fourier_length();
        for (mut acc, key_poly) in self
            .iter_fourier_poly_mut(fourier_length)
            .zip(rhs.iter_fourier_poly(fourier_length))
        {
            acc.add_mul_assign(poly, &key_poly);
        }
    }
}
