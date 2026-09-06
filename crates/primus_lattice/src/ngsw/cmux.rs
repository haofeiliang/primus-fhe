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
    ntru::{
        Ntru,
        gadget_product::{accumulate_fourier_gadget_product, accumulate_ntt_gadget_product},
    },
};

use super::{FourierNgsw, NttNgsw};

impl<S> FourierNgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` encrypts the control bit. Zero selects `ct0`, and one selects
    /// `ct1`. Inputs and output are coefficient-domain native-torus NTRU
    /// ciphertexts.
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and context must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `context.poly_length()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or context reset is needed.
    /// `self` must encrypt a bit; this is not checked.
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
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let poly_length = context.poly_length();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_to(ct0, output, NativeModulus::new());
        context.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(self.as_ref(), output.as_ref(), basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(ct0, NativeModulus::new());
    }

    /// Selects among `default` and `candidates` using encrypted control bits.
    ///
    /// This evaluates
    /// `default + sum_j controls[j] * (candidates[j] - default)`.
    ///
    /// `controls[j]` encrypts the bit selecting `candidates[j]`. At most one
    /// control bit may be nonzero. An all-zero control vector selects
    /// `default`; otherwise the unique nonzero bit selects its corresponding
    /// candidate.
    ///
    /// # Correctness
    ///
    /// Each control and every coefficient-domain input/output must satisfy
    /// [`Self::cmux_to`], using the same basis, table, and context layout.
    /// Controls and candidates have equal counts and matching order. Each
    /// control encrypts a bit, with at most one bit equal to one; bit values
    /// and exclusivity are not checked. Empty lists copy `default` exactly.
    /// Output is overwritten and context scratch needs no manual reset.
    ///
    /// # Panics
    ///
    /// Panics if the reported control count differs from `candidates.len()`,
    /// or if empty-list copying encounters unequal default/output lengths.
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
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: Borrow<Self>,
    {
        let controls = controls.into_iter();
        assert_eq!(
            controls.len(),
            candidates.len(),
            "CMUX requires one control per candidate"
        );
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
            candidate.sub_to(default, output, NativeModulus::new());
            let control: &Self = control.borrow();
            accumulate_fourier_gadget_product(
                control.as_ref(),
                output.as_ref(),
                basis,
                fft,
                context,
            );
        }
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(default, NativeModulus::new());
    }

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    ///
    /// # Correctness
    ///
    /// The control, input, output, basis, table, and context must satisfy
    /// [`Self::cmux_to`]. Require `exponent < 2 * N`, where `N` is the
    /// context polynomial length. Bit zero selects `input`; bit one selects
    /// `input * X^exponent`. Output is overwritten; no reset is required.
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
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        input.mul_monomial_sub_one_to(exponent, output, NativeModulus::new());
        context.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(self.as_ref(), output.as_ref(), basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(input, NativeModulus::new());
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
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and context must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `context.poly_length()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or context reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
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
        S: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let poly_length = context.poly_length();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_to(ct0, output, modulus);
        context.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(self.as_ref(), output.as_ref(), basis, modulus, ntt, context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(ct0, modulus);
    }

    /// Selects among `default` and `candidates` using encrypted control bits.
    ///
    /// This evaluates
    /// `default + sum_j controls[j] * (candidates[j] - default)`.
    ///
    /// `controls[j]` encrypts the bit selecting `candidates[j]`. At most one
    /// control bit may be nonzero. An all-zero control vector selects
    /// `default`; otherwise the unique nonzero bit selects its corresponding
    /// candidate.
    ///
    /// # Correctness
    ///
    /// Each control and every coefficient-domain input/output must satisfy
    /// [`Self::cmux_to`], using the same basis, table, and context layout.
    /// Controls and candidates have equal counts and matching order. Each
    /// control encrypts a bit, with at most one bit equal to one; bit values
    /// and exclusivity are not checked. Empty lists copy `default` exactly.
    /// Output is overwritten and context scratch needs no manual reset.
    ///
    /// # Panics
    ///
    /// Panics if the reported control count differs from `candidates.len()`,
    /// or if empty-list copying encounters unequal default/output lengths.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
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
        S: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
        I: IntoIterator,
        I::IntoIter: ExactSizeIterator,
        I::Item: Borrow<Self>,
    {
        let controls = controls.into_iter();
        assert_eq!(
            controls.len(),
            candidates.len(),
            "CMUX requires one control per candidate"
        );
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
            candidate.sub_to(default, output, modulus);
            let control: &Self = control.borrow();
            accumulate_ntt_gadget_product(
                control.as_ref(),
                output.as_ref(),
                basis,
                modulus,
                ntt,
                context,
            );
        }
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(default, modulus);
    }

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    ///
    /// # Correctness
    ///
    /// The control, input, output, basis, table, and context must satisfy
    /// [`Self::cmux_to`]. Require `exponent < 2 * N`, where `N` is the
    /// context polynomial length. Bit zero selects `input`; bit one selects
    /// `input * X^exponent`. Output is overwritten; no reset is required.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
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
        S: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        input.mul_monomial_sub_one_to(exponent, output, modulus);
        context.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(self.as_ref(), output.as_ref(), basis, modulus, ntt, context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
