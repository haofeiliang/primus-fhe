use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_factor::FactorSliceOps;
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{
    ArrayBase, CrtPolynomial, CrtPolynomialIter, CrtPolynomialIterMut, DcrtPolynomial,
};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{context::DcrtGlevMulContext, ggsw::DcrtGgsw};

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

impl_common!(CrtGlwe<S>);
impl_bytes_conversion!(CrtGlwe<S>);
impl_zero!(CrtGlwe<S>);
impl_iters!(CrtGlwe);
impl_iter_sub_structure!(CrtGlwe<S>, CrtPolynomial, crt_poly);
impl_basic_operation_multiple_modulus!(CrtGlwe<S>);
impl_crt_ntt!(CrtGlwe<S>, DcrtGlwe);

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

    /// Multiplies each CRT polynomial component by `scalar_residue` in place.
    pub fn mul_scalar_assign<M>(
        &mut self,
        scalar_residue: &[T],
        poly_length: usize,
        crt_poly_len: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
    {
        self.iter_crt_poly_mut(crt_poly_len)
            .for_each(|mut crt_poly| {
                crt_poly.mul_scalar_assign(scalar_residue, poly_length, moduli);
            });
    }

    /// Perform `self = self * X^r`.
    pub fn mul_monic_monomial_assign<M>(
        &mut self,
        r: usize,
        poly_length: usize,
        crt_poly_length: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
    {
        if r < poly_length {
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[0..r]);
            };

            self.iter_crt_poly_mut(crt_poly_length)
                .for_each(|mut crt_poly| {
                    crt_poly
                        .iter_each_modulus_mut(poly_length)
                        .zip(moduli)
                        .for_each(|(poly, &modulus)| rotate(poly, modulus));
                });
        } else {
            debug_assert!(r < poly_length * 2);
            let r = r - poly_length;
            let rotate = |poly: &mut [T], modulus: M| {
                poly.rotate_right(r);
                modulus.reduce_neg_slice_assign(&mut poly[r..]);
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

    /// Multiplies this CRT GLWE by a scalar residue and writes the result into `result`.
    pub fn mul_scalar_to<M, A>(
        &self,
        scalar_residue: &[T],
        result: &mut CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        moduli: &[M],
    ) where
        M: FieldContext<T>,
        A: DataMut<Elem = T>,
    {
        self.iter_crt_poly(crt_poly_len)
            .zip(result.iter_crt_poly_mut(crt_poly_len))
            .for_each(|(in_crt_poly, mut out_crt_poly)| {
                in_crt_poly.mul_scalar_to(scalar_residue, &mut out_crt_poly, poly_length, moduli);
            });
    }

    /// Multiplies this CRT GLWE by a Shoup factor and writes the result into `result`.
    pub fn mul_factor_to<F, A>(
        &self,
        scalar: &[F],
        result: &mut CrtGlwe<A>,
        poly_length: usize,
        crt_poly_len: usize,
        moduli: &[T],
    ) where
        F: Copy + FactorSliceOps<T>,
        A: DataMut<Elem = T>,
    {
        self.iter_crt_poly(crt_poly_len)
            .zip(result.iter_crt_poly_mut(crt_poly_len))
            .for_each(|(in_crt_poly, mut out_crt_poly)| {
                in_crt_poly.mul_factor_to(scalar, &mut out_crt_poly, poly_length, moduli);
            });
    }

    /// Performs a multiplication on the `self` [`CrtGlwe<S>`] with another `dcrt_poly` [`DcrtPolynomial<A>`],
    /// store the result into `result` [`DcrtGlwe<T>`].
    #[inline]
    pub fn mul_dcrt_polynomial_to<M, Table, A, B>(
        &self,
        dcrt_poly: &DcrtPolynomial<A>,
        result: &mut DcrtGlwe<B>,
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

        result.0.copy_from_slice(self.as_ref());

        result.iter_dcrt_poly_mut(dcrt_poly_len).for_each(|mut x| {
            table.transform_slice(x.0);
            x.mul_assign(dcrt_poly, poly_length, moduli);
        });
    }

    /// Multiplies this CRT GLWE by a DCRT GGSW ciphertext, storing the result into `result`.
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    pub fn mul_dcrt_ggsw_to<M, Table, A, B>(
        &self,
        dcrt_ggsw: &DcrtGgsw<A>,
        result: &mut DcrtGlwe<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlevMulContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let crt_poly_len = table.crt_poly_length();
        let dcrt_glev_len = basis.decompose_length() * self.as_ref().len();

        result.set_zero();

        dcrt_ggsw
            .iter_dcrt_glev(dcrt_glev_len)
            .zip(self.iter_crt_poly(crt_poly_len))
            .for_each(|(dcrt_glev, crt_poly)| {
                result.add_dcrt_glev_mul_crt_poly_assign(
                    &dcrt_glev, &crt_poly, basis, table, rns_base, context,
                );
            });
    }
}
