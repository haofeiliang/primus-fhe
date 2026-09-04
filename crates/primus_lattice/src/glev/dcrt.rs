use itertools::izip;
use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{ArrayBase, BigUintPolynomial, CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use crate::{
    context::{DcrtGlevMulContext, DcrtGlevMulContextRefMut},
    glwe::{DcrtGlwe, DcrtGlweIter, DcrtGlweIterMut},
};

use super::CrtGlev;

/// A representation of Module Learning with Errors (MLWE) ciphertexts with respect to different base,
/// used to control noise growth in polynomial multiplications.
///
/// ## Structure of the `data`
///
/// |--c1--|....|--cd--|
///
/// where `c1` to `cd` are [`crate::glwe::DcrtGlwe`] with same parameter, `d` is the decompose length.
#[derive(Clone)]
pub struct DcrtGlev<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(DcrtGlev<S>);
impl_bytes_conversion!(DcrtGlev<S>);
impl_zero!(DcrtGlev<S>);
impl_iters!(DcrtGlev);
impl_iter_sub_structure!(DcrtGlev<S>, DcrtGlwe);
impl_basic_operation_multiple_modulus!(DcrtGlev<S>);
impl_crt_intt!(DcrtGlev<S>, CrtGlev);

impl<S, T> DcrtGlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Multiplies this DCRT GLEV with a CRT-domain polynomial, storing the result into `result`.
    pub fn mul_crt_poly_to<M, Table, A, B>(
        &self,
        crt_poly: &CrtPolynomial<A>,
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
        let poly_length = table.poly_length();
        let basis_value = basis.basis_value();
        let moduli = rns_base.moduli();
        let dcrt_glwe_len = result.0.len();

        let DcrtGlevMulContextRefMut {
            adjust_big_uint_values,
            decomposed_unsigned_values,
            carries,
            multi_residues,
            compose_buffer,
        } = context.as_mut();

        rns_base.compose_big_uint_values_to(
            crt_poly.as_ref(),
            adjust_big_uint_values,
            poly_length,
            compose_buffer,
        );

        basis.init_value_carry_slice_inplace(adjust_big_uint_values, carries);

        result.set_zero();

        self.iter_dcrt_glwe(dcrt_glwe_len)
            .zip(basis.decomposer_iter())
            .for_each(|(dcrt_glwe, once_decomposer)| {
                once_decomposer.unsigned_decompose_slice_to(
                    adjust_big_uint_values,
                    decomposed_unsigned_values,
                    carries,
                );

                rns_base.wrapping_decompose_small_values_to(
                    decomposed_unsigned_values,
                    multi_residues,
                    basis_value,
                );

                table.transform_slice(multi_residues);

                result.add_dcrt_glwe_mul_dcrt_polynomial_assign(
                    &dcrt_glwe,
                    &DcrtPolynomial(&*multi_residues),
                    poly_length,
                    moduli,
                );
            });
    }

    /// Multiplies this DCRT GLEV with a BigUint-domain polynomial, storing the result into `result`.
    pub fn mul_big_uint_poly_to<M, Table, A, B>(
        &self,
        big_uint_poly: &BigUintPolynomial<A>,
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
        let poly_length = table.poly_length();
        let dcrt_glwe_len = result.0.len();
        let basis_value = basis.basis_value();
        let moduli = rns_base.moduli();

        let DcrtGlevMulContextRefMut {
            adjust_big_uint_values,
            decomposed_unsigned_values,
            carries,
            multi_residues,
            compose_buffer: _,
        } = context.as_mut();

        basis.init_value_carry_slice_to(big_uint_poly.as_slice(), adjust_big_uint_values, carries);

        result.set_zero();

        self.iter_dcrt_glwe(dcrt_glwe_len)
            .zip(basis.decomposer_iter())
            .for_each(|(dcrt_glwe, once_decomposer)| {
                once_decomposer.unsigned_decompose_slice_to(
                    adjust_big_uint_values,
                    decomposed_unsigned_values,
                    carries,
                );

                rns_base.wrapping_decompose_small_values_to(
                    decomposed_unsigned_values,
                    multi_residues,
                    basis_value,
                );

                table.transform_slice(multi_residues);

                result.add_dcrt_glwe_mul_dcrt_polynomial_assign(
                    &dcrt_glwe,
                    &DcrtPolynomial(&*multi_residues),
                    poly_length,
                    moduli,
                );
            });
    }
}
