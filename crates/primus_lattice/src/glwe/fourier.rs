use num_complex::Complex64;
use primus_data::{Data, DataMut, RawData};

use primus_poly::{FourierPolynomial, FourierPolynomialIter, FourierPolynomialIterMut};

#[allow(unused_imports)]
use super::Glwe;

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

impl_fourier_core!(FourierGlwe);

impl_fourier_iters!(FourierGlwe);
impl_fourier_iter_sub!(
    FourierGlwe,
    FourierPolynomial,
    FourierPolynomialIter,
    FourierPolynomialIterMut,
    fourier_poly
);

impl_fourier_basic_operation!(FourierGlwe);

impl_fourier_conversion!(Glwe, FourierGlwe);

// ---------------------------------------------------------------------------
// GLWE-specific methods
// ---------------------------------------------------------------------------

impl<S> FourierGlwe<S>
where
    S: Data<Elem = Complex64>,
{
    /// Splits this GLWE into its mask and body slices.
    #[inline]
    pub fn a_b_slices(&self, fourier_length: usize) -> (&[Complex64], &[Complex64]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(fourier_length > 0);
        debug_assert!(glwe_len > fourier_length);
        debug_assert!(glwe_len.is_multiple_of(fourier_length));
        self.as_ref().split_at(glwe_len - fourier_length)
    }

    /// Splits this GLWE into its mask polynomials and body polynomial.
    #[inline]
    pub fn a_b(
        &self,
        fourier_length: usize,
    ) -> (FourierPolynomialIter<'_>, FourierPolynomial<&[Complex64]>) {
        let (mask, body) = self.a_b_slices(fourier_length);
        (
            FourierPolynomialIter::new(mask, fourier_length),
            FourierPolynomial(body),
        )
    }
}

impl<S> FourierGlwe<S>
where
    S: DataMut<Elem = Complex64>,
{
    /// Splits this GLWE into its mutable mask and body slices.
    #[inline]
    pub fn a_b_mut_slices(
        &mut self,
        fourier_length: usize,
    ) -> (&mut [Complex64], &mut [Complex64]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(fourier_length > 0);
        debug_assert!(glwe_len > fourier_length);
        debug_assert!(glwe_len.is_multiple_of(fourier_length));
        self.as_mut().split_at_mut(glwe_len - fourier_length)
    }

    /// Splits this GLWE into its mutable mask polynomials and body polynomial.
    #[inline]
    pub fn a_b_mut(
        &mut self,
        fourier_length: usize,
    ) -> (
        FourierPolynomialIterMut<'_>,
        FourierPolynomial<&mut [Complex64]>,
    ) {
        let (mask, body) = self.a_b_mut_slices(fourier_length);
        (
            FourierPolynomialIterMut::new(mask, fourier_length),
            FourierPolynomial(body),
        )
    }

    /// Performs `self += rhs * poly` for each component (pointwise FMA).
    ///
    /// This is the core operation in the TFHE external product hot loop:
    /// the accumulator GLWE accumulates the product of a decomposed FFT
    /// polynomial with a GGSW key GLWE.
    #[inline]
    pub fn add_mul_fourier_polynomial_assign<A, B>(
        &mut self,
        rhs: &FourierGlwe<A>,
        poly: &FourierPolynomial<B>,
    ) where
        A: Data<Elem = Complex64>,
        B: Data<Elem = Complex64>,
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
