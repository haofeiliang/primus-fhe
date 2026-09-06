use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
#[allow(unused_imports)]
use primus_poly::{NttPolynomial, Polynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::{FieldContext, RingContext};

use super::NttGlwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`Polynomial`] with same poly length, `k` is the dimension.
#[derive(Clone)]
pub struct Glwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_ciphertext_core!(Glwe);

impl_iters!(Glwe);
impl_iter_sub_structure!(Glwe, Polynomial, poly);

impl_basic_operation_single_modulus!(Glwe);
impl_neg_single_modulus!(Glwe);
impl_mul_scalar_single_modulus!(Glwe);
impl_mul_factor_single_modulus!(Glwe);
impl_add_mul_monomial_single_modulus!(Glwe);

impl_ntt!(Glwe, NttGlwe);

impl<S, T> Glwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mutable mask and body slices.
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
    ) -> (PolynomialIterMut<'_, T>, Polynomial<&mut [T]>) {
        let (mask, body) = self.a_b_mut_slices(poly_length);
        (PolynomialIterMut::new(mask, poly_length), Polynomial(body))
    }
}

impl<S, T> Glwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Splits this GLWE into its mask and body slices.
    #[inline]
    pub fn a_b_slices(&self, poly_length: usize) -> (&[T], &[T]) {
        let glwe_len = self.as_ref().len();
        debug_assert!(poly_length > 0);
        debug_assert!(glwe_len > poly_length);
        debug_assert!(glwe_len.is_multiple_of(poly_length));
        self.as_ref().split_at(glwe_len - poly_length)
    }

    /// Splits this GLWE into its mask polynomials and body polynomial.
    #[inline]
    pub fn a_b(&self, poly_length: usize) -> (PolynomialIter<'_, T>, Polynomial<&[T]>) {
        let (mask, body) = self.a_b_slices(poly_length);
        (PolynomialIter::new(mask, poly_length), Polynomial(body))
    }

    /// Multiplies every GLWE component by `X^exponent` in
    /// `Z_q[X]/(X^N + 1)` and writes the output to `output`.
    ///
    /// `exponent` must belong to `[0, 2N)`.
    pub fn mul_monomial_to<M, B>(
        &self,
        exponent: usize,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        self.monomial_to::<false, M, B>(exponent, output, poly_length, modulus);
    }

    /// Computes `output = self * (X^exponent - 1)` component-wise in
    /// `Z_q[X]/(X^N + 1)`.
    ///
    /// `exponent` must belong to `[0, 2N)`. Rotation and subtraction are
    /// fused into one coefficient pass.
    pub fn mul_monomial_sub_one_to<M, B>(
        &self,
        exponent: usize,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        self.monomial_to::<true, M, B>(exponent, output, poly_length, modulus);
    }

    #[inline]
    fn monomial_to<const SUBTRACT_SELF: bool, M, B>(
        &self,
        exponent: usize,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(
            (crate::MIN_POLY_LENGTH..=crate::MAX_POLY_LENGTH).contains(&poly_length)
                && poly_length.is_power_of_two()
        );
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(self.as_ref().len(), output.as_ref().len());
        debug_assert!(self.as_ref().len().is_multiple_of(poly_length));

        for (input, output) in self
            .as_ref()
            .chunks_exact(poly_length)
            .zip(output.as_mut().chunks_exact_mut(poly_length))
        {
            if SUBTRACT_SELF {
                Polynomial(input).mul_monomial_sub_one_to(
                    exponent,
                    &mut Polynomial(output),
                    modulus,
                );
            } else {
                Polynomial(input).mul_monomial_to(exponent, &mut Polynomial(output), modulus);
            }
        }
    }

    /// Performs a multiplication on the `self` [`Glwe<S>`] with another `ntt_poly` [`NttPolynomial<A>`],
    /// store the output into `output` [`NttGlwe<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        output: &mut NttGlwe<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let ntt_poly_len = ntt_table.poly_length();

        output.0.copy_from_slice(self.as_ref());

        output.iter_ntt_poly_mut(ntt_poly_len).for_each(|mut poly| {
            ntt_table.transform_slice(poly.0);
            poly.mul_assign(ntt_poly, modulus);
        });
    }
}
