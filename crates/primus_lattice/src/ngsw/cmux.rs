//! NGSW-controlled conditional multiplexers in the Fourier and NTT domains.

use core::borrow::Borrow;

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{
    context::{FourierNtruExternalProductContext, NttNtruExternalProductContext},
    ntru::Ntru,
};

use super::{FourierNgsw, NttNgsw};

impl<S> FourierNgsw<S>
where
    S: RawData<Elem = Complex64>,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` encrypts the control bit. Zero selects `ct0`, and one selects
    /// `ct1`. Inputs and output are coefficient-domain native-torus NTRU
    /// ciphertexts.
    pub fn cmux_to<T, Table, B, C, D>(
        &self,
        ct0: &Ntru<B>,
        ct1: &Ntru<C>,
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        S: Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
    {
        let poly_length = context.poly_length();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_element_wise_to(ct0, output, NativeModulus::new());
        self.external_product_accumulate(output, basis, fft, context);
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
        default: &Ntru<B>,
        candidates: &[Ntru<C>],
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        S: Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: Borrow<Self>,
    {
        let controls = controls.into_iter();
        assert_eq!(controls.len(), candidates.len());
        let poly_length = context.poly_length();
        debug_assert_eq!(default.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);
        debug_assert!(
            candidates
                .iter()
                .all(|candidate| candidate.as_ref().len() == poly_length)
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

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    pub fn cmux_monomial_to<T, Table, B, C>(
        &self,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        S: Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        input.mul_monomial_sub_one_to(exponent, output, NativeModulus::new());
        self.external_product_accumulate(output, basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_element_wise_assign(input, NativeModulus::new());
    }
}

impl<S> NttNgsw<S>
where
    S: RawData,
    S::Elem: FheUint,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` encrypts the control bit. Zero selects `ct0`, and one selects
    /// `ct1`. Inputs and output are coefficient-domain NTRU ciphertexts.
    pub fn cmux_to<T, M, Table, B, C, D>(
        &self,
        ct0: &Ntru<B>,
        ct1: &Ntru<C>,
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + Data,
        D: RawData<Elem = T> + DataMut,
    {
        let poly_length = context.poly_length();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_element_wise_to(ct0, output, modulus);
        self.external_product_accumulate(output, basis, modulus, ntt, context);
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
        default: &Ntru<B>,
        candidates: &[Ntru<C>],
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruExternalProductContext<T>,
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
        let poly_length = context.poly_length();
        debug_assert_eq!(default.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);
        debug_assert!(
            candidates
                .iter()
                .all(|candidate| candidate.as_ref().len() == poly_length)
        );

        if candidates.is_empty() {
            output.as_mut().copy_from_slice(default.as_ref());
            return;
        }

        context.ntt_accumulator.set_zero();
        for (control, candidate) in controls.zip(candidates) {
            candidate.sub_element_wise_to(default, output, modulus);
            let control: &Self = control.borrow();
            control.external_product_add_assign(output, basis, modulus, ntt, context);
        }
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_element_wise_assign(default, modulus);
    }

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    pub fn cmux_monomial_to<T, M, Table, B, C>(
        &self,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
    {
        input.mul_monomial_sub_one_to(exponent, output, modulus);
        self.external_product_accumulate(output, basis, modulus, ntt, context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_element_wise_assign(input, modulus);
    }
}
