use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{ArrayBase, NttPolynomial, NttPolynomialIter, NttPolynomialIterMut};
use primus_reduce::FieldContext;

use super::Glwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`NttPolynomial`] with same poly length, `k` is the dimension.
#[derive(Clone)]
pub struct NttGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(NttGlwe<S>);
impl_bytes_conversion!(NttGlwe<S>);
impl_zero!(NttGlwe<S>);
impl_iters!(NttGlwe);
impl_iter_sub_structure!(NttGlwe<S>, NttPolynomial, ntt_poly);
impl_basic_operation_single_modulus!(NttGlwe<S>);
impl_intt!(NttGlwe<S>, Glwe);

impl<S, T> NttGlwe<S>
where
    S: RawData<Elem = T> + DataMut,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
    ///
    /// The body is the final NTT polynomial and therefore has exactly
    /// `poly_length` coefficients.
    #[inline]
    pub fn a_b_mut_slices(&mut self, poly_length: usize) -> (&mut [T], &mut [T]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(poly_length > 0);
        debug_assert!(glwe_len > poly_length);
        debug_assert!(glwe_len.is_multiple_of(poly_length));
        self.as_mut().split_at_mut(glwe_len - poly_length)
    }

    /// Splits this GLWE into its mutable mask polynomials and body polynomial.
    #[inline]
    pub fn a_b_mut(
        &mut self,
        poly_length: usize,
    ) -> (NttPolynomialIterMut<'_, T>, NttPolynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(poly_length);
        (
            NttPolynomialIterMut::new(mask, poly_length),
            NttPolynomial(body),
        )
    }

    /// Performs a modular multiplication on the `self` [`NttGlwe<S>`] with another `ntt_poly` [`NttPolynomial<A>`].
    #[inline]
    pub fn mul_ntt_polynomial_assign<M, A>(&mut self, ntt_poly: &NttPolynomial<A>, modulus: M)
    where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
    {
        let poly_len = ntt_poly.poly_length();

        self.iter_ntt_poly_mut(poly_len).for_each(|mut poly| {
            poly.mul_assign(ntt_poly, modulus);
        });
    }

    /// Performs `self += ntt_poly * rhs` component-wise.
    ///
    /// This is the NTT-domain multiply-accumulate used by the TFHE external
    /// product hot loop.
    #[inline]
    pub fn add_mul_ntt_polynomial_assign<M, A, B>(
        &mut self,
        ntt_poly: &NttPolynomial<A>,
        rhs: &NttGlwe<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
    {
        let poly_length = ntt_poly.poly_length();
        debug_assert_eq!(self.as_ref().len(), rhs.as_ref().len());
        debug_assert_eq!(self.as_ref().len() % poly_length, 0);

        self.iter_ntt_poly_mut(poly_length)
            .zip(rhs.iter_ntt_poly(poly_length))
            .for_each(|(mut accumulator, rhs)| {
                accumulator.add_mul_assign(ntt_poly, &rhs, modulus);
            });
    }
}

impl<S, T> NttGlwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    ///
    /// The body is the final NTT polynomial and therefore has exactly
    /// `poly_length` coefficients.
    #[inline]
    pub fn a_b_slices(&self, poly_length: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(poly_length > 0);
        debug_assert!(glwe_len > poly_length);
        debug_assert!(glwe_len.is_multiple_of(poly_length));
        self.0.split_at(glwe_len - poly_length)
    }

    /// Splits this GLWE into its mask polynomials and body polynomial.
    #[inline]
    pub fn a_b(&self, poly_length: usize) -> (NttPolynomialIter<'_, T>, NttPolynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(poly_length);
        (
            NttPolynomialIter::new(mask, poly_length),
            NttPolynomial(body),
        )
    }

    /// Performs a modular multiplication on the `self` [`NttGlwe<S>`] with another `ntt_poly` [`NttPolynomial`],
    /// stores the result into `result`.
    #[inline]
    pub fn mul_ntt_polynomial_to<M, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttGlwe<B>,
        modulus: M,
    ) where
        M: FieldContext<T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let poly_length = ntt_poly.poly_length();

        self.iter_ntt_poly(poly_length)
            .zip(result.iter_ntt_poly_mut(poly_length))
            .for_each(|(x, mut y)| {
                x.mul_to(ntt_poly, &mut y, modulus);
            });
    }
}
