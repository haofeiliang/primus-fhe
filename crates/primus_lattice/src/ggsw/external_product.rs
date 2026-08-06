//! GGSW external products in the Fourier and NTT domains.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial};
use primus_reduce::FieldContext;

use crate::{
    context::{FourierExternalProductContext, NttExternalProductContext},
    glwe::{Glwe, TorusGlwe},
};

use super::{FourierGgsw, NttGgsw};

impl<S> FourierGgsw<S>
where
    S: RawData<Elem = Complex64>,
{
    /// Computes `output = self external_product input`.
    ///
    /// This operation uses the implicit native torus modulus. `input` and
    /// `output` are coefficient-domain torus GLWE ciphertexts. `basis` must be
    /// the decomposition basis used to construct `self`.
    pub fn external_product_to<T, Table, A, C>(
        &self,
        input: &TorusGlwe<A>,
        output: &mut TorusGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
        S: RawData<Elem = Complex64> + Data,
    {
        debug_assert_eq!(output.as_ref().len(), context.size().glwe_size().glwe_len());
        self.external_product_accumulate(input, basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
    }

    /// Clears the Fourier accumulator, then stores `self external_product input` in it.
    /// The result remains in Fourier form for the caller to combine or transform back.
    pub(super) fn external_product_accumulate<T, Table, A>(
        &self,
        input: &TorusGlwe<A>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        S: RawData<Elem = Complex64> + Data,
    {
        context.fourier_accumulator.set_zero();
        self.external_product_add_assign(input, basis, fft, context);
    }

    /// Adds `self external_product input` to the existing Fourier accumulator.
    /// This does not clear the accumulator; the caller must initialize it first.
    pub(super) fn external_product_add_assign<T, Table, A>(
        &self,
        input: &TorusGlwe<A>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: RawData<Elem = T> + Data,
        S: RawData<Elem = Complex64> + Data,
    {
        let size = context.size();
        let glwe_size = size.glwe_size();
        let poly_len = glwe_size.poly_length();
        let fourier_poly_len = glwe_size.fourier_poly_len();
        let fourier_glwe_len = glwe_size.fourier_glwe_len();
        let fourier_glev_len = size.fourier_glev_len();

        debug_assert_eq!(fft.poly_length(), poly_len);
        debug_assert_eq!(fft.fourier_length(), fourier_poly_len);
        debug_assert_eq!(basis.modulus(), None);
        debug_assert_eq!(basis.decompose_length(), size.decompose_length());
        debug_assert_eq!(input.as_ref().len(), glwe_size.glwe_len());
        debug_assert_eq!(self.as_ref().len(), size.fourier_ggsw_len());

        for (coeff_poly, key_row) in input
            .iter_poly(poly_len)
            .zip(self.iter_glev(fourier_glev_len))
        {
            basis.init_carry_slice(coeff_poly.0, &mut context.carries);
            for (decomposer, key_glwe) in basis
                .decompose_iter()
                .zip(key_row.iter_glwe(fourier_glwe_len))
            {
                decomposer.decompose_slice_to(
                    coeff_poly.0,
                    &mut context.decomposed_poly,
                    &mut context.carries,
                );
                fft.forward_as_integer(&context.decomposed_poly, &mut context.decomposed_fourier);
                context.fourier_accumulator.add_mul_fourier_poly_assign(
                    &FourierPolynomial::new(context.decomposed_fourier.as_slice()),
                    &key_glwe,
                );
            }
        }
    }
}

impl<S> NttGgsw<S>
where
    S: RawData,
    S::Elem: FheUint,
{
    /// Computes `output = self external_product input`.
    ///
    /// The input and output are coefficient-domain GLWE ciphertexts with every
    /// coefficient reduced to `[0, q)`. `basis` and `modulus` must match those
    /// used to construct `self`.
    pub fn external_product_to<T, M, Table, A, C>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
        S: RawData<Elem = T> + Data,
    {
        debug_assert_eq!(output.as_ref().len(), context.size().glwe_size().glwe_len());
        self.external_product_accumulate(input, basis, modulus, ntt, context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
    }

    /// Clears the NTT accumulator, then stores `self external_product input` in it.
    /// The result remains in NTT form for the caller to combine or transform back.
    pub(super) fn external_product_accumulate<T, M, Table, A>(
        &self,
        input: &Glwe<A>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        S: RawData<Elem = T> + Data,
    {
        context.ntt_accumulator.set_zero();
        self.external_product_add_assign(input, basis, modulus, ntt, context);
    }

    /// Adds `self external_product input` to the existing NTT accumulator.
    /// This does not clear the accumulator; the caller must initialize it first.
    pub(super) fn external_product_add_assign<T, M, Table, A>(
        &self,
        input: &Glwe<A>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        S: RawData<Elem = T> + Data,
    {
        let size = context.size();
        let glwe_size = size.glwe_size();
        let poly_len = glwe_size.poly_length();
        let glwe_len = glwe_size.glwe_len();
        let glev_len = size.glev_len();

        debug_assert_eq!(ntt.poly_length(), poly_len);
        debug_assert_eq!(basis.modulus(), Some(modulus.value()));
        debug_assert_eq!(basis.decompose_length(), size.decompose_length());
        debug_assert_eq!(input.as_ref().len(), glwe_len);
        debug_assert_eq!(self.as_ref().len(), size.ggsw_len());

        for (coeff_poly, key_row) in input.iter_poly(poly_len).zip(self.iter_ntt_glev(glev_len)) {
            basis.init_value_carry_slice_to(
                coeff_poly.as_ref(),
                &mut context.adjusted_poly,
                &mut context.carries,
            );
            for (decomposer, key_glwe) in
                basis.decompose_iter().zip(key_row.iter_ntt_glwe(glwe_len))
            {
                decomposer.decompose_slice_to(
                    &context.adjusted_poly,
                    &mut context.decomposed_ntt,
                    &mut context.carries,
                );
                ntt.transform_slice(&mut context.decomposed_ntt);
                let digit = NttPolynomial::new(context.decomposed_ntt.as_slice());
                context
                    .ntt_accumulator
                    .add_mul_ntt_polynomial_assign(&digit, &key_glwe, modulus);
            }
        }
    }
}
