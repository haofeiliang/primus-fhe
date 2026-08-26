//! GGSW-controlled conditional multiplexers in the Fourier and NTT domains.

use core::borrow::Borrow;

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
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
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` is a Fourier GGSW encryption of a bit. A control bit of zero
    /// selects `ct0`, while a control bit of one selects `ct1`. The GLWE inputs
    /// and output use the implicit native torus modulus and coefficient form.
    pub fn cmux_to<T, Table, B, C, D>(
        &self,
        ct0: &TorusGlwe<B>,
        ct1: &TorusGlwe<C>,
        output: &mut TorusGlwe<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        S: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
    {
        let glwe_len = context.size().glwe_size().glwe_len();
        debug_assert_eq!(ct0.as_ref().len(), glwe_len);
        debug_assert_eq!(ct1.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);

        ct1.sub_element_wise_to(ct0, output, NativeModulus::new());
        self.external_product_to_accumulator(output, basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_element_wise_assign(ct0, NativeModulus::new());
    }

    /// Computes a `k`-to-1 CMux with `default` as candidate zero.
    ///
    /// This evaluates
    /// `default + sum_j controls[j] * (candidates[j] - default)`.
    ///
    /// `controls[j]` encrypts the bit selecting `candidates[j]`. At most one
    /// control bit may be nonzero. An all-zero control vector selects
    /// `default`; otherwise the unique nonzero bit selects its corresponding
    /// candidate.
    pub fn cmux_k_to<T, Table, B, C, D, I>(
        controls: I,
        default: &TorusGlwe<B>,
        candidates: &[TorusGlwe<C>],
        output: &mut TorusGlwe<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        S: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: Borrow<Self>,
    {
        let controls = controls.into_iter();
        assert_eq!(controls.len(), candidates.len());
        let glwe_len = context.size().glwe_size().glwe_len();
        debug_assert_eq!(default.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);
        debug_assert!(
            candidates
                .iter()
                .all(|candidate| candidate.as_ref().len() == glwe_len)
        );

        if candidates.is_empty() {
            output.as_mut().copy_from_slice(default.as_ref());
            return;
        }

        context.fourier_accumulator.set_zero();
        for (control, candidate) in controls.zip(candidates) {
            candidate.sub_element_wise_to(default, output, NativeModulus::new());
            let control: &Self = control.borrow();
            control.external_product_add_assign(output, basis, fft, context);
        }
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_element_wise_assign(default, NativeModulus::new());
    }

    /// Computes `output = input + self external_product
    /// (input * (X^exponent - 1))` for the native-torus Fourier backend.
    ///
    /// This is the CMUX form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    pub fn cmux_monomial_to<T, Table, B, C>(
        &self,
        input: &TorusGlwe<B>,
        exponent: usize,
        output: &mut TorusGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        S: RawData<Elem = Complex64> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let poly_length = context.size().glwe_size().poly_length();

        input.mul_monomial_sub_one_to(exponent, output, poly_length, NativeModulus::new());
        self.external_product_to_accumulator(output, basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_element_wise_assign(input, NativeModulus::new());
    }
}

impl<S> NttGgsw<S>
where
    S: RawData,
    S::Elem: FheUint,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` is an NTT GGSW encryption of a bit. A control bit of zero selects
    /// `ct0`, while a control bit of one selects `ct1`. Every coefficient-domain
    /// GLWE coefficient must be reduced to `[0, q)`.
    pub fn cmux_to<T, M, Table, B, C, D>(
        &self,
        ct0: &Glwe<B>,
        ct1: &Glwe<C>,
        output: &mut Glwe<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
    {
        let glwe_len = context.size().glwe_size().glwe_len();
        debug_assert_eq!(ct0.as_ref().len(), glwe_len);
        debug_assert_eq!(ct1.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);

        ct1.sub_element_wise_to(ct0, output, modulus);
        let mut context = context.as_mut();
        self.external_product_to_accumulator(output, basis, modulus, ntt, &mut context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_element_wise_assign(ct0, modulus);
    }

    /// Computes a `k`-to-1 CMux with `default` as candidate zero.
    ///
    /// This evaluates
    /// `default + sum_j controls[j] * (candidates[j] - default)`.
    ///
    /// `controls[j]` encrypts the bit selecting `candidates[j]`. At most one
    /// control bit may be nonzero. An all-zero control vector selects
    /// `default`; otherwise the unique nonzero bit selects its corresponding
    /// candidate.
    pub fn cmux_k_to<T, M, Table, B, C, D, I>(
        controls: I,
        default: &Glwe<B>,
        candidates: &[Glwe<C>],
        output: &mut Glwe<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: Borrow<Self>,
    {
        let controls = controls.into_iter();
        assert_eq!(controls.len(), candidates.len());
        let glwe_len = context.size().glwe_size().glwe_len();
        debug_assert_eq!(default.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);
        debug_assert!(
            candidates
                .iter()
                .all(|candidate| candidate.as_ref().len() == glwe_len)
        );

        if candidates.is_empty() {
            output.as_mut().copy_from_slice(default.as_ref());
            return;
        }

        let mut context = context.as_mut();
        context.ntt_accumulator.set_zero();
        for (control, candidate) in controls.zip(candidates) {
            candidate.sub_element_wise_to(default, output, modulus);
            let control: &Self = control.borrow();
            control.external_product_add_assign(output, basis, modulus, ntt, &mut context);
        }
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_element_wise_assign(default, modulus);
    }

    /// Computes `output = input + self external_product
    /// (input * (X^exponent - 1))` for the NTT backend.
    ///
    /// This is the CMUX form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    pub fn cmux_monomial_to<T, M, Table, B, C>(
        &self,
        input: &Glwe<B>,
        exponent: usize,
        output: &mut Glwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        let poly_length = context.size().glwe_size().poly_length();

        input.mul_monomial_sub_one_to(exponent, output, poly_length, modulus);
        let mut context = context.as_mut();
        self.external_product_to_accumulator(output, basis, modulus, ntt, &mut context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_element_wise_assign(input, modulus);
    }
}
