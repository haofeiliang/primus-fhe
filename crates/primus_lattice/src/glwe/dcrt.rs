use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_factor::ShoupFactor;
use primus_integer::FheUint;
use primus_poly::{DcrtPolynomial, DcrtPolynomialIter, DcrtPolynomialIterMut};
use primus_reduce::FieldContext;

use super::CrtGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`DcrtPolynomial`] with same poly length and moduli count, `k` is the dimension.
#[derive(Clone)]
pub struct DcrtGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(DcrtGlwe);

impl_iters!(DcrtGlwe);
impl_iter_sub_structure!(DcrtGlwe, DcrtPolynomial, dcrt_poly);

impl_basic_operation_multiple_modulus!(DcrtGlwe);
impl_neg_multiple_modulus!(DcrtGlwe);
impl_mul_scalar_multiple_modulus!(DcrtGlwe);
impl_mul_factor_multiple_modulus!(DcrtGlwe);
impl_dcrt_polynomial_mul!(DcrtGlwe);

impl_crt_intt!(DcrtGlwe, CrtGlwe);

impl<S, T> DcrtGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
    #[inline]
    pub fn a_b_mut_slices(&mut self, dcrt_poly_len: usize) -> (&mut [T], &mut [T]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(dcrt_poly_len > 0);
        debug_assert!(glwe_len > dcrt_poly_len);
        debug_assert!(glwe_len.is_multiple_of(dcrt_poly_len));
        self.as_mut().split_at_mut(glwe_len - dcrt_poly_len)
    }

    /// Splits this GLWE into its mutable mask polynomials and body polynomial.
    #[inline]
    pub fn a_b_mut(
        &mut self,
        dcrt_poly_len: usize,
    ) -> (DcrtPolynomialIterMut<'_, T>, DcrtPolynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(dcrt_poly_len);
        (
            DcrtPolynomialIterMut::new(mask, dcrt_poly_len),
            DcrtPolynomial(body),
        )
    }

    /// Inverse butterfly with monomial multiply.
    /// `(self, output) = (self + rhs, (self_orig - rhs) * dcrt_poly)`
    pub fn butterfly_mul_dcrt_polynomial_to<M, A, B, C>(
        &mut self,
        rhs: &DcrtGlwe<A>,
        dcrt_poly: &DcrtPolynomial<B>,
        output: &mut DcrtGlwe<C>,
        poly_length: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let dcrt_poly_len = dcrt_poly.dcrt_poly_length();
        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .zip(rhs.iter_dcrt_poly(dcrt_poly_len))
            .zip(output.iter_dcrt_poly_mut(dcrt_poly_len))
            .for_each(|((mut a, s), mut b)| {
                a.butterfly_mul_to(&s, dcrt_poly, &mut b, poly_length, moduli);
            });
    }

    /// Inverse butterfly with a Shoup-factor DCRT polynomial.
    /// `(self, output) = (self + rhs, (self_orig - rhs) * factor_poly)`.
    ///
    /// `self` and `rhs` are expected in `[0, q)`. Both outputs are written
    /// back in `[0, q)`.
    pub fn butterfly_mul_factor_to<A, C>(
        &mut self,
        rhs: &DcrtGlwe<A>,
        factor_poly: &[ShoupFactor<T>],
        output: &mut DcrtGlwe<C>,
        poly_length: usize,
        moduli: &[T],
    ) where
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let dcrt_poly_len = factor_poly.len();
        self.iter_dcrt_poly_mut(dcrt_poly_len)
            .zip(rhs.iter_dcrt_poly(dcrt_poly_len))
            .zip(output.iter_dcrt_poly_mut(dcrt_poly_len))
            .for_each(|((mut a, s), mut b)| {
                a.butterfly_mul_factor_to(&s, factor_poly, &mut b, poly_length, moduli);
            });
    }
}

impl<S, T> DcrtGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    #[inline]
    pub fn a_b_slices(&self, dcrt_poly_len: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(dcrt_poly_len > 0);
        debug_assert!(glwe_len > dcrt_poly_len);
        debug_assert!(glwe_len.is_multiple_of(dcrt_poly_len));
        self.as_ref().split_at(glwe_len - dcrt_poly_len)
    }

    /// Splits this GLWE into its mask polynomials and body polynomial.
    #[inline]
    pub fn a_b(&self, dcrt_poly_len: usize) -> (DcrtPolynomialIter<'_, T>, DcrtPolynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(dcrt_poly_len);
        (
            DcrtPolynomialIter::new(mask, dcrt_poly_len),
            DcrtPolynomial(body),
        )
    }
}
