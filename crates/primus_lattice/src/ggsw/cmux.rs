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
    context::{FourierGlweExternalProductContext, NttGlweExternalProductContext},
    glwe::{Glwe, TorusGlwe},
};

use super::{FourierGgsw, NttGgsw};

impl<S> FourierGgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` is a Fourier GGSW encryption of a bit. A control bit of zero
    /// selects `ct0`, while a control bit of one selects `ct1`. The GLWE inputs
    /// and output use the implicit native torus modulus and coefficient form.
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and context must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `context.size().glwe_size().glwe_len()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or context reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    pub fn cmux_to<T, Table, B, C, D>(
        &self,
        ct0: &TorusGlwe<B>,
        ct1: &TorusGlwe<C>,
        output: &mut TorusGlwe<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let glwe_len = context.size().glwe_size().glwe_len();
        debug_assert_eq!(ct0.as_ref().len(), glwe_len);
        debug_assert_eq!(ct1.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);

        ct1.sub_to(ct0, output, NativeModulus::new());
        context.fourier_accumulator.set_zero();
        self.accumulate_external_product(output, basis, fft, context);
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
        default: &TorusGlwe<B>,
        candidates: &[TorusGlwe<C>],
        output: &mut TorusGlwe<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweExternalProductContext<T>,
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
            candidate.sub_to(default, output, NativeModulus::new());
            let control: &Self = control.borrow();
            control.accumulate_external_product(output, basis, fft, context);
        }
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(default, NativeModulus::new());
    }

    /// Computes `output = input + self external_product
    /// (input * (X^exponent - 1))` for the native-torus Fourier backend.
    ///
    /// This is the CMUX form used by blind rotation. `exponent` must belong to
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
        input: &TorusGlwe<B>,
        exponent: usize,
        output: &mut TorusGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierGlweExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = context.size().glwe_size().poly_length();

        input.mul_monomial_sub_one_to(exponent, output, poly_length, NativeModulus::new());
        context.fourier_accumulator.set_zero();
        self.accumulate_external_product(output, basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(input, NativeModulus::new());
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
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and context must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `context.size().glwe_size().glwe_len()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or context reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_to<T, M, Table, B, C, D>(
        &self,
        ct0: &Glwe<B>,
        ct1: &Glwe<C>,
        output: &mut Glwe<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: Data<Elem = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let glwe_len = context.size().glwe_size().glwe_len();
        debug_assert_eq!(ct0.as_ref().len(), glwe_len);
        debug_assert_eq!(ct1.as_ref().len(), glwe_len);
        debug_assert_eq!(output.as_ref().len(), glwe_len);

        ct1.sub_to(ct0, output, modulus);
        let mut context = context.as_mut();
        context.ntt_accumulator.set_zero();
        self.accumulate_external_product(output, basis, modulus, ntt, &mut context);
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
        default: &Glwe<B>,
        candidates: &[Glwe<C>],
        output: &mut Glwe<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweExternalProductContext<T>,
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
            candidate.sub_to(default, output, modulus);
            let control: &Self = control.borrow();
            control.accumulate_external_product(output, basis, modulus, ntt, &mut context);
        }
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(default, modulus);
    }

    /// Computes `output = input + self external_product
    /// (input * (X^exponent - 1))` for the NTT backend.
    ///
    /// This is the CMUX form used by blind rotation. `exponent` must belong to
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
        input: &Glwe<B>,
        exponent: usize,
        output: &mut Glwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        S: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = context.size().glwe_size().poly_length();

        input.mul_monomial_sub_one_to(exponent, output, poly_length, modulus);
        let mut context = context.as_mut();
        context.ntt_accumulator.set_zero();
        self.accumulate_external_product(output, basis, modulus, ntt, &mut context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
