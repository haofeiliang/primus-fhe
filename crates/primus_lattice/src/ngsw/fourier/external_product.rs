//! NGSW external products in the Fourier domain.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};

use crate::nlev::Nlev;
use crate::ntru::{FourierNtru, Ntru, accumulate_fourier_gadget_product};
use crate::workspace::FourierNtruExternalProductWorkspace;

use super::FourierNgsw;

impl<S> FourierNgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes `output = input external_product self` using the native torus modulus.
    ///
    /// `input` and `output` are coefficient-domain scalar NTRU ciphertexts.
    /// `basis` must be the decomposition basis used to construct this NGSW
    /// ciphertext.
    ///
    /// # Correctness
    ///
    /// Let `N = workspace.poly_length().get()` and `L = basis.decompose_length().get()`.
    /// The input and output each contain exactly `N` coefficients.
    /// `self` contains exactly `L * N / 2` complex values, grouped
    /// by level in `basis.decomposer_iter()` order. The basis must be the
    /// one used to construct the gadget ciphertext. The input and NGSW
    /// control must use compatible NTRU keys.
    /// `basis` must use the implicit native modulus (`basis.modulus() == None`).
    /// The FFT engine must have polynomial length `N` and Fourier length
    /// `N / 2`; gadget values must use its packing and normalized torus scale.
    /// Output is overwritten and workspace scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, Table, A, C>(
        &self,
        input: &Ntru<A>,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        debug_assert_eq!(output.as_ref().len(), workspace.poly_length().get());
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            input.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
        workspace.fourier_accumulator.write_torus_form(output, fft);
    }

    /// Computes the external product directly in this key's Fourier representation.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::external_product_to`]'s input, key, basis, table and
    /// workspace contracts. Output contains exactly `N / 2` complex values at
    /// torus scale. It is used directly as the accumulator, without an inverse
    /// transform or torus rounding; subsequent Fourier operations use the same table.
    ///
    /// # Panics
    /// Panics if the output length is not `workspace.poly_length().fourier_poly_len()`.
    pub fn external_product_fourier_to<T, Table, A, C>(
        &self,
        input: &Ntru<A>,
        output: &mut FourierNtru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = Complex64>,
    {
        assert_eq!(
            output.as_ref().len(),
            workspace.poly_length().fourier_poly_len(),
            "external-product output length mismatch"
        );
        let mut workspace = workspace.as_mut_with_accumulator(output);
        workspace.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            input.as_ref(),
            basis,
            fft,
            &mut workspace,
        );
    }

    /// Applies this NGSW external product to every NTRU level in `input`.
    ///
    /// If `input` encrypts `alpha` as NLev and `self` encrypts `beta` as
    /// NGSW, `output` encrypts `alpha * beta` as NLev.
    ///
    /// # Correctness
    ///
    /// The gadget, basis, table, and workspace must satisfy
    /// [`Self::external_product_to`]. Input and output have the same number of
    /// complete `workspace.poly_length().get()`-coefficient levels in matching NLev
    /// order under compatible keys. Their level count and gadget scalars are
    /// independent of the control's `basis`, and are preserved by this operation.
    /// Each output level is overwritten; workspace scratch needs no manual reset.
    pub fn external_product_nlev_to<T, Table, A, C>(
        &self,
        input: &Nlev<A>,
        output: &mut Nlev<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierNtruExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = workspace.poly_length().get();
        debug_assert_eq!(input.as_ref().len() & (poly_length - 1), 0);
        debug_assert_eq!(output.as_ref().len(), input.as_ref().len());

        let mut workspace = workspace.as_mut();
        for (input_level, mut output_level) in input
            .iter_ntru(poly_length)
            .zip(output.iter_ntru_mut(poly_length))
        {
            workspace.fourier_accumulator.set_zero();
            accumulate_fourier_gadget_product(
                self.as_ref(),
                input_level.as_ref(),
                basis,
                fft,
                &mut workspace,
            );
            workspace
                .fourier_accumulator
                .write_torus_form(&mut output_level, fft);
        }
    }
}
