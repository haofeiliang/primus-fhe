//! NGSW-controlled conditional multiplexers in the Fourier and NTT domains.
//!
//! The output buffer holds the coefficient difference during decomposition, so
//! these operations use the workspace-owned accumulator instead of borrowing output.

use core::borrow::Borrow;

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{
    ntru::{
        Ntru,
        gadget_product::{accumulate_fourier_gadget_product, accumulate_ntt_gadget_product},
    },
    workspace::{FourierNtruExternalProductWorkspace, NttNtruExternalProductWorkspace},
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
    /// The control ciphertext, basis, transform table, and workspace must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `workspace.poly_length()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or workspace reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    pub fn cmux_to<T, Table, B, C, D>(
        &self,
        ct0: &Ntru<B>,
        ct1: &Ntru<C>,
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_to(ct0, output, NativeModulus::new());
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
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
    /// [`Self::cmux_to`], using the same basis, table, and workspace layout.
    /// Controls and candidates have equal counts and matching order. Each
    /// control encrypts a bit, with at most one bit equal to one; bit values
    /// and exclusivity are not checked. Empty lists copy `default` exactly.
    /// Controls may be borrowed objects or semantic iterators over packed storage.
    /// Candidate items convert to shared views via `Into`; use `as_view()` and
    /// `as_mut_view()` for owned default and output ciphertexts.
    /// Callers constructing chunk iterators must exclude incomplete trailing objects.
    /// Output is overwritten and workspace scratch needs no manual reset. Products
    /// are summed in the transform domain before a single inverse transform.
    /// Fourier rounding can differ from summing separately converted products.
    ///
    /// # Panics
    ///
    /// Panics on unequal reported iterator counts or incorrect object lengths.
    /// Counts and default/output lengths are checked before writes; individual
    /// controls/candidates are checked as consumed, so a panic can leave partial output.
    pub fn cmux_k_to<'a, T, Table, I, J>(
        controls: I,
        default: Ntru<&[T]>,
        candidates: J,
        mut output: Ntru<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        I: IntoIterator<Item: Borrow<Self>, IntoIter: ExactSizeIterator>,
        J: IntoIterator<Item: Into<Ntru<&'a [T]>>, IntoIter: ExactSizeIterator>,
    {
        let controls = controls.into_iter();
        let candidates = candidates.into_iter();
        assert_eq!(
            controls.len(),
            candidates.len(),
            "CMUX requires one control per candidate"
        );
        let poly_length = workspace.poly_length();
        assert_eq!(
            default.as_ref().len(),
            poly_length,
            "CMUX default length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            poly_length,
            "CMUX output length mismatch"
        );

        if candidates.len() == 0 {
            output.as_mut().copy_from_slice(default.as_ref());
            return;
        }

        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        // Keep default unchanged: each decomposed difference is relative to
        // the same c_0. Clear once above and invert only after the entire sum.
        for (control, candidate) in controls.zip(candidates) {
            let candidate = candidate.into();
            assert_eq!(
                candidate.as_ref().len(),
                poly_length,
                "CMUX candidate length mismatch"
            );
            candidate.sub_to(&default, &mut output, NativeModulus::new());
            let control: &Self = control.borrow();
            assert_eq!(
                control.as_ref().len(),
                basis.decompose_length() * (poly_length / 2),
                "CMUX control length mismatch"
            );
            accumulate_fourier_gadget_product(
                control.as_ref(),
                output.as_ref(),
                basis,
                fft,
                &mut workspace,
            );
        }
        workspace
            .fourier_accumulator
            .write_torus_form(&mut output, fft);
        output.add_assign(&default, NativeModulus::new());
    }

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    ///
    /// # Correctness
    ///
    /// The control, input, output, basis, table, and workspace must satisfy
    /// [`Self::cmux_to`]. Require `exponent < 2 * N`, where `N` is the
    /// workspace polynomial length. Bit zero selects `input`; bit one selects
    /// `input * X^exponent`. Output is overwritten; no reset is required.
    pub fn cmux_monomial_to<T, Table, B, C>(
        &self,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        input.mul_monomial_sub_one_to(exponent, output, NativeModulus::new());
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
        output.add_assign(input, NativeModulus::new());
    }
}

impl<S, T> NttNgsw<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Computes `output = ct0 + self external_product (ct1 - ct0)`.
    ///
    /// `self` encrypts the control bit. Zero selects `ct0`, and one selects
    /// `ct1`. Inputs and output are coefficient-domain NTRU ciphertexts.
    ///
    /// # Correctness
    ///
    /// The control ciphertext, basis, transform table, and workspace must satisfy
    /// [`Self::external_product_to`]. Every coefficient-domain input and output
    /// has exactly `workspace.poly_length()` elements, with compatible keys,
    /// moduli, and encodings. Values must be canonical residues. The output
    /// is overwritten; no prior output initialization or workspace reset is needed.
    /// `self` must encrypt a bit; this is not checked.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_to<M, Table, B, C, D>(
        &self,
        ct0: &Ntru<B>,
        ct1: &Ntru<C>,
        output: &mut Ntru<D>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: Data<Elem = T>,
        C: Data<Elem = T>,
        D: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length();
        debug_assert_eq!(ct0.as_ref().len(), poly_length);
        debug_assert_eq!(ct1.as_ref().len(), poly_length);
        debug_assert_eq!(output.as_ref().len(), poly_length);

        ct1.sub_to(ct0, output, modulus);
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
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
    /// [`Self::cmux_to`], using the same basis, table, and workspace layout.
    /// Controls and candidates have equal counts and matching order. Each
    /// control encrypts a bit, with at most one bit equal to one; bit values
    /// and exclusivity are not checked. Empty lists copy `default` exactly.
    /// Controls may be borrowed objects or semantic iterators over packed storage.
    /// Candidate items convert to shared views via `Into`; use `as_view()` and
    /// `as_mut_view()` for owned default and output ciphertexts.
    /// Callers constructing chunk iterators must exclude incomplete trailing objects.
    /// Output is overwritten and workspace scratch needs no manual reset. Products
    /// are summed in the transform domain before a single inverse transform.
    ///
    /// # Panics
    ///
    /// Panics on unequal reported iterator counts or incorrect object lengths.
    /// Counts and default/output lengths are checked before writes; individual
    /// controls/candidates are checked as consumed, so a panic can leave partial output.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_k_to<'a, M, Table, I, J>(
        controls: I,
        default: Ntru<&[T]>,
        candidates: J,
        mut output: Ntru<&mut [T]>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        I: IntoIterator<Item: Borrow<Self>, IntoIter: ExactSizeIterator>,
        J: IntoIterator<Item: Into<Ntru<&'a [T]>>, IntoIter: ExactSizeIterator>,
    {
        let controls = controls.into_iter();
        let candidates = candidates.into_iter();
        assert_eq!(
            controls.len(),
            candidates.len(),
            "CMUX requires one control per candidate"
        );
        let poly_length = workspace.poly_length();
        assert_eq!(
            default.as_ref().len(),
            poly_length,
            "CMUX default length mismatch"
        );
        assert_eq!(
            output.as_ref().len(),
            poly_length,
            "CMUX output length mismatch"
        );

        if candidates.len() == 0 {
            output.as_mut().copy_from_slice(default.as_ref());
            return;
        }

        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        // Keep default unchanged: each decomposed difference is relative to
        // the same c_0. Clear once above and invert only after the entire sum.
        for (control, candidate) in controls.zip(candidates) {
            let candidate = candidate.into();
            assert_eq!(
                candidate.as_ref().len(),
                poly_length,
                "CMUX candidate length mismatch"
            );
            candidate.sub_to(&default, &mut output, modulus);
            let control: &Self = control.borrow();
            assert_eq!(
                control.as_ref().len(),
                basis.decompose_length() * poly_length,
                "CMUX control length mismatch"
            );
            accumulate_ntt_gadget_product(
                control.as_ref(),
                output.as_ref(),
                basis,
                modulus,
                ntt,
                &mut workspace,
            );
        }
        workspace.ntt_accumulator.write_coeff_form(&mut output, ntt);
        output.add_assign(&default, modulus);
    }

    /// Computes `output = input + self external_product (input * (X^exponent - 1))`.
    ///
    /// This is the CMux form used by blind rotation. `exponent` must belong to
    /// `[0, 2N)`.
    ///
    /// # Correctness
    ///
    /// The control, input, output, basis, table, and workspace must satisfy
    /// [`Self::cmux_to`]. Require `exponent < 2 * N`, where `N` is the
    /// workspace polynomial length. Bit zero selects `input`; bit one selects
    /// `input * X^exponent`. Output is overwritten; no reset is required.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep operands, decomposition basis, arithmetic, transform, and scratch explicit"
    )]
    pub fn cmux_monomial_to<M, Table, B, C>(
        &self,
        input: &Ntru<B>,
        exponent: usize,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttNtruExternalProductWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        input.mul_monomial_sub_one_to(exponent, output, modulus);
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            output.as_ref(),
            basis,
            modulus,
            ntt,
            &mut workspace,
        );
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
        output.add_assign(input, modulus);
    }
}
