use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut, DcrtPolynomial};
use primus_reduce::FieldContext;

use super::DcrtGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`primus_poly::CrtPolynomial`] with same poly length and moduli count, `k` is the dimension.
#[derive(Clone)]
pub struct CrtGlwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(CrtGlwe);

impl_iters!(CrtGlwe);
impl_iter_sub_structure!(CrtGlwe, CrtPolynomial, crt_poly);

impl_basic_operation_multiple_modulus!(CrtGlwe);
impl_neg_multiple_modulus!(CrtGlwe);
impl_mul_scalar_multiple_modulus!(CrtGlwe);
impl_mul_factor_multiple_modulus!(CrtGlwe);

impl_crt_ntt!(CrtGlwe, DcrtGlwe);

impl<S, T> CrtGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
    #[inline]
    pub fn a_b_mut_slices(&mut self, crt_poly_len: usize) -> (&mut [T], &mut [T]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(crt_poly_len > 0);
        debug_assert!(glwe_len > crt_poly_len);
        debug_assert!(glwe_len.is_multiple_of(crt_poly_len));
        self.as_mut().split_at_mut(glwe_len - crt_poly_len)
    }

    /// Splits this GLWE into its mutable mask polynomials and body polynomial.
    #[inline]
    pub fn a_b_mut(
        &mut self,
        crt_poly_len: usize,
    ) -> (CrtPolynomialIterMut<'_, T>, CrtPolynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(crt_poly_len);
        (
            CrtPolynomialIterMut::new(mask, crt_poly_len),
            CrtPolynomial(body),
        )
    }

    /// Perform `self = self * X^exponent`.
    pub fn mul_monomial_assign<M>(
        &mut self,
        exponent: usize,
        poly_length: usize,
        crt_poly_length: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
    {
        if exponent < poly_length {
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(exponent);
                modulus.reduce_neg_slice_assign(&mut poly[0..exponent]);
            };

            self.iter_crt_poly_mut(crt_poly_length)
                .for_each(|mut crt_poly| {
                    crt_poly
                        .iter_each_modulus_mut(poly_length)
                        .zip(moduli)
                        .for_each(|(poly, &modulus)| rotate(poly, modulus));
                });
        } else {
            debug_assert!(exponent < poly_length * 2);
            let exponent = exponent - poly_length;
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(exponent);
                modulus.reduce_neg_slice_assign(&mut poly[exponent..]);
            };

            self.iter_crt_poly_mut(crt_poly_length)
                .for_each(|mut crt_poly| {
                    crt_poly
                        .iter_each_modulus_mut(poly_length)
                        .zip(moduli)
                        .for_each(|(poly, &modulus)| rotate(poly, modulus));
                });
        }
    }
}

impl<S, T> CrtGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    #[inline]
    pub fn a_b_slices(&self, crt_poly_len: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(crt_poly_len > 0);
        debug_assert!(glwe_len > crt_poly_len);
        debug_assert!(glwe_len.is_multiple_of(crt_poly_len));
        self.as_ref().split_at(glwe_len - crt_poly_len)
    }

    /// Splits this GLWE into its mask polynomials and body polynomial.
    #[inline]
    pub fn a_b(&self, crt_poly_len: usize) -> (CrtPolynomialIter<'_, T>, CrtPolynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(crt_poly_len);
        (
            CrtPolynomialIter::new(mask, crt_poly_len),
            CrtPolynomial(body),
        )
    }

    /// Performs a multiplication on the `self` [`CrtGlwe<S>`] with another `dcrt_poly` [`DcrtPolynomial<A>`],
    /// store the output into `output` [`DcrtGlwe<T>`].
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, Table, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        output: &mut DcrtGlwe<B>,
        moduli: &[M],
        table: &DcrtTable<Table>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let poly_length = table.poly_length();
        let dcrt_poly_len = table.crt_poly_length();

        output.0.copy_from_slice(self.as_ref());

        output.iter_dcrt_poly_mut(dcrt_poly_len).for_each(|mut x| {
            table.transform_slice(x.0);
            x.mul_assign(dcrt_poly, poly_length, moduli);
        });
    }
}
