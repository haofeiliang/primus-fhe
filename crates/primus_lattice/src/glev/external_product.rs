//! DCRT GLev products with CRT and BigUint coefficient polynomials.

use primus_data::{Data, DataMut};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_integer::FheUint;
use primus_ntt::{DcrtTable, NttTable};
use primus_poly::{BigUintPolynomial, CrtPolynomial, DcrtPolynomial};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;

use super::DcrtGlev;
use crate::{
    context::{DcrtGlevMulContext, DcrtGlevMulContextRefMut},
    glwe::DcrtGlwe,
};

impl<S, T> DcrtGlev<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Multiplies this DCRT GLEV with a CRT-domain polynomial, storing the output into `output`.
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    /// `context` must support the output gadget size and the current RNS limb
    /// width; the table must match its polynomial length and ordered RNS base.
    /// The output is overwritten; scratch does not require a manual reset.
    pub fn mul_crt_polynomial_to<M, Table, A, B>(
        &self,
        crt_poly: &CrtPolynomial<A>,
        output: &mut DcrtGlwe<B>,
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
        output.set_zero();
        output.add_dcrt_glev_mul_crt_polynomial_assign(
            self, crt_poly, basis, table, rns_base, context,
        );
    }

    /// Multiplies this DCRT GLEV with a BigUint-domain polynomial, storing the output into `output`.
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    /// `context` must support the output gadget size and the current RNS limb
    /// width; the table must match its polynomial length and ordered RNS base.
    /// The output is overwritten; scratch does not require a manual reset.
    pub fn mul_big_uint_polynomial_to<M, Table, A, B>(
        &self,
        big_uint_poly: &BigUintPolynomial<A>,
        output: &mut DcrtGlwe<B>,
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
        output.set_zero();
        output.add_dcrt_glev_mul_big_uint_polynomial_assign(
            self,
            big_uint_poly,
            basis,
            table,
            rns_base,
            context,
        );
    }
}

impl<S, T> DcrtGlwe<S>
where
    S: DataMut<Elem = T>,
    T: FheUint,
{
    /// Performs `self += dcrt_glev * crt_poly` using the given decomposition basis and NTT table.
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    /// `context` must support the output gadget size and the current RNS limb
    /// width; the table must match its polynomial length and ordered RNS base.
    /// The output must be initialized; scratch does not require a manual reset.
    pub fn add_dcrt_glev_mul_crt_polynomial_assign<M, Table, A, B>(
        &mut self,
        dcrt_glev: &DcrtGlev<A>,
        crt_poly: &CrtPolynomial<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlevMulContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        let poly_length = table.poly_length();
        let basis_value = basis.basis_value();

        let moduli = rns_base.moduli();
        let dcrt_glwe_len = self.0.len();

        let size = context.size();
        debug_assert!(
            context.is_compatible(size, rns_base),
            "incompatible DCRT workspace"
        );
        debug_assert_eq!(size.rns_glwe_size().poly_length(), poly_length);
        debug_assert_eq!(size.rns_glwe_size().rns_glwe_len(), dcrt_glwe_len);
        debug_assert_eq!(size.decompose_length(), basis.decompose_length());

        let DcrtGlevMulContextRefMut {
            adjust_big_uint_values,
            decomposed_unsigned_values,
            carries,
            multi_residues,
            compose_buffer,
        } = context.as_mut();

        debug_assert_eq!(
            dcrt_glev.as_ref().len(),
            dcrt_glwe_len * basis.decompose_length()
        );

        rns_base.compose_big_uint_values_to(
            crt_poly.as_ref(),
            adjust_big_uint_values,
            poly_length,
            compose_buffer,
        );

        basis.init_value_carry_slice_assign(adjust_big_uint_values, carries);

        dcrt_glev
            .iter_dcrt_glwe(dcrt_glwe_len)
            .zip(basis.decomposer_iter())
            .for_each(|(dcrt_glwe, once_decomposer)| {
                once_decomposer.unsigned_decompose_slice_to(
                    adjust_big_uint_values.as_ref(),
                    decomposed_unsigned_values,
                    carries,
                );

                rns_base.wrapping_decompose_small_values_to(
                    decomposed_unsigned_values.as_ref(),
                    multi_residues,
                    basis_value,
                );

                table.transform_slice(multi_residues);

                self.add_mul_dcrt_polynomial_assign(
                    &dcrt_glwe,
                    &DcrtPolynomial(&*multi_residues),
                    poly_length,
                    moduli,
                );
            });
    }

    /// Performs `self += dcrt_glev * big_uint_poly` using the given decomposition basis and NTT table.
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    /// `context` must support the output gadget size and the current RNS limb
    /// width; the table must match its polynomial length and ordered RNS base.
    /// The output must be initialized; scratch does not require a manual reset.
    pub fn add_dcrt_glev_mul_big_uint_polynomial_assign<M, Table, A, B>(
        &mut self,
        dcrt_glev: &DcrtGlev<A>,
        big_uint_poly: &BigUintPolynomial<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        context: &mut DcrtGlevMulContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
    {
        let poly_length = table.poly_length();
        let big_uint_value_len = rns_base.big_uint_value_len();
        let big_uint_poly_len = big_uint_poly.len();
        let basis_value = basis.basis_value();

        debug_assert_eq!(big_uint_poly_len, big_uint_value_len * poly_length);

        let moduli = rns_base.moduli();
        let dcrt_glwe_len = self.0.len();

        let size = context.size();
        debug_assert!(
            context.is_compatible(size, rns_base),
            "incompatible DCRT workspace"
        );
        debug_assert_eq!(size.rns_glwe_size().poly_length(), poly_length);
        debug_assert_eq!(size.rns_glwe_size().rns_glwe_len(), dcrt_glwe_len);
        debug_assert_eq!(size.decompose_length(), basis.decompose_length());

        let DcrtGlevMulContextRefMut {
            adjust_big_uint_values,
            decomposed_unsigned_values,
            carries,
            multi_residues,
            compose_buffer: _,
        } = context.as_mut();

        debug_assert_eq!(
            dcrt_glev.as_ref().len(),
            dcrt_glwe_len * basis.decompose_length()
        );

        basis.init_value_carry_slice_to(big_uint_poly.as_slice(), adjust_big_uint_values, carries);

        dcrt_glev
            .iter_dcrt_glwe(dcrt_glwe_len)
            .zip(basis.decomposer_iter())
            .for_each(|(dcrt_glwe, once_decomposer)| {
                once_decomposer.unsigned_decompose_slice_to(
                    adjust_big_uint_values.as_ref(),
                    decomposed_unsigned_values,
                    carries,
                );

                rns_base.wrapping_decompose_small_values_to(
                    decomposed_unsigned_values.as_ref(),
                    multi_residues,
                    basis_value,
                );

                table.transform_slice(multi_residues);

                self.add_mul_dcrt_polynomial_assign(
                    &dcrt_glwe,
                    &DcrtPolynomial(&*multi_residues),
                    poly_length,
                    moduli,
                );
            });
    }
}
