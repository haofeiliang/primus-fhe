//! GGSW external products in the Fourier, NTT, and DCRT domains.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial};
use primus_reduce::FieldContext;

use crate::{
    glwe::{FourierGlwe, Glwe, NttGlwe, TorusGlwe},
    workspace::{
        FourierGlweExternalProductWorkspace, FourierGlweExternalProductWorkspaceRefMut,
        NttGlweExternalProductWorkspace, NttGlweExternalProductWorkspaceRefMut,
    },
};

use super::{FourierGgsw, NttGgsw};

#[cfg(feature = "rns")]
use crate::{
    ggsw::DcrtGgsw,
    glwe::{CrtGlwe, DcrtGlwe},
    workspace::DcrtGlevMulWorkspace,
};
#[cfg(feature = "rns")]
use primus_decompose::big_integer::BigUintApproxSignedBasis;
#[cfg(feature = "rns")]
use primus_ntt::DcrtTable;
#[cfg(feature = "rns")]
use primus_rns::RNSBase;

impl<S> FourierGgsw<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes `output = self external_product input`.
    ///
    /// This operation uses the implicit native torus modulus. `input` and
    /// `output` are coefficient-domain torus GLWE ciphertexts. `basis` must be
    /// the decomposition basis used to construct `self`.
    ///
    /// # Correctness
    ///
    /// Let `size = workspace.size()`, `N = size.glwe_size().poly_length()`,
    /// and `L = size.decompose_length()`. Input and output each have
    /// `size.glwe_size().glwe_len()` elements; `self` has exactly
    /// `size.fourier_ggsw_len()` elements. The `k + 1` GLev rows correspond
    /// to the input mask polynomials followed by its body, with `L` levels
    /// per row in `basis.decomposer_iter()` order. Keys must be compatible.
    /// `basis` must use the implicit native modulus (`basis.modulus() == None`).
    /// The FFT engine must have polynomial length `N` and Fourier length
    /// `N / 2`; gadget values must use its packing and normalized torus scale.
    /// Output is overwritten and workspace scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, Table, A, C>(
        &self,
        input: &TorusGlwe<A>,
        output: &mut TorusGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().glwe_len()
        );
        let mut workspace = workspace.as_mut();
        workspace.fourier_accumulator.set_zero();
        self.accumulate_external_product(input, basis, fft, &mut workspace);
        workspace.fourier_accumulator.write_torus_form(output, fft);
    }

    /// Computes an external product directly into Fourier output, without an inverse FFT.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::external_product_to`]'s contracts, except that output
    /// has `workspace.size().glwe_size().fourier_glwe_len()` complex values in
    /// the key's FFT representation. Output is cleared before accumulation.
    pub fn external_product_fourier_to<T, Table, A, C>(
        &self,
        input: &TorusGlwe<A>,
        output: &mut FourierGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspace<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = Complex64>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().fourier_glwe_len()
        );
        let mut workspace = workspace.as_mut_with_accumulator(output);
        workspace.fourier_accumulator.set_zero();
        self.accumulate_external_product(input, basis, fft, &mut workspace);
    }

    /// Adds `self external_product input` to the existing Fourier accumulator.
    /// This does not clear the accumulator; the caller must initialize it first.
    ///
    /// # Correctness
    ///
    /// The input, gadget, basis, table, and workspace must satisfy
    /// [`Self::external_product_to`]. The workspace accumulator takes the role
    /// of output and must have the corresponding transform-domain layout.
    pub(super) fn accumulate_external_product<T, Table, A>(
        &self,
        input: &TorusGlwe<A>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        workspace: &mut FourierGlweExternalProductWorkspaceRefMut<'_, T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
    {
        let size = workspace.size();
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
            basis.init_carry_slice(coeff_poly.0, workspace.carries);
            for (decomposer, key_glwe) in basis
                .decomposer_iter()
                .zip(key_row.iter_glwe(fourier_glwe_len))
            {
                decomposer.decompose_slice_to(
                    coeff_poly.0,
                    workspace.decomposed_poly,
                    workspace.carries,
                );
                fft.forward_as_integer(workspace.decomposed_poly, workspace.decomposed_fourier);
                workspace
                    .fourier_accumulator
                    .add_mul_fourier_polynomial_assign(
                        &key_glwe,
                        &FourierPolynomial::new(&*workspace.decomposed_fourier),
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
    ///
    /// # Correctness
    ///
    /// Let `size = workspace.size()`, `N = size.glwe_size().poly_length()`,
    /// and `L = size.decompose_length()`. Input and output each have
    /// `size.glwe_size().glwe_len()` elements; `self` has exactly
    /// `size.ggsw_len()` elements. The `k + 1` GLev rows correspond
    /// to the input mask polynomials followed by its body, with `L` levels
    /// per row in `basis.decomposer_iter()` order. Keys must be compatible.
    /// `basis`, `modulus`, and the NTT table must use the same modulus.
    /// The NTT polynomial length must be `N`, and gadget evaluations must
    /// use that table's order. Input and gadget values must be canonical residues.
    /// Output is overwritten and workspace scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, M, Table, A, C>(
        &self,
        input: &Glwe<A>,
        output: &mut Glwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        S: Data<Elem = T>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().glwe_len()
        );
        let mut workspace = workspace.as_mut();
        workspace.ntt_accumulator.set_zero();
        self.accumulate_external_product(input, basis, modulus, ntt, &mut workspace);
        workspace.ntt_accumulator.write_coeff_form(output, ntt);
    }

    /// Computes `output = self external_product input` and keeps the output in
    /// the NTT domain.
    ///
    /// The input is a coefficient-domain GLWE ciphertext reduced to `[0, q)`.
    /// The output is overwritten in NTT form. This variant avoids the inverse
    /// transform performed by [`Self::external_product_to`] when a composed
    /// operation consumes the product in the NTT domain.
    ///
    /// # Correctness
    ///
    /// All contracts of [`Self::external_product_to`] apply, except that the
    /// output uses the supplied table's NTT representation. It must contain
    /// exactly `workspace.size().glwe_size().glwe_len()` elements. The caller
    /// need not initialize output; the product clears it before accumulating.
    pub fn external_product_ntt_to<T, M, Table, A, C>(
        &self,
        input: &Glwe<A>,
        output: &mut NttGlwe<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspace<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        S: Data<Elem = T>,
    {
        debug_assert_eq!(
            output.as_ref().len(),
            workspace.size().glwe_size().glwe_len()
        );
        let mut workspace = workspace.as_mut_with_accumulator(output);
        workspace.ntt_accumulator.set_zero();
        self.accumulate_external_product(input, basis, modulus, ntt, &mut workspace);
    }

    /// Adds `self external_product input` to the existing NTT accumulator.
    /// This does not clear the accumulator; the caller must initialize it first.
    ///
    /// # Correctness
    ///
    /// The input, gadget, basis, table, and workspace must satisfy
    /// [`Self::external_product_to`]. The workspace accumulator takes the role
    /// of output and must have the corresponding transform-domain layout.
    pub(super) fn accumulate_external_product<T, M, Table, A>(
        &self,
        input: &Glwe<A>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        workspace: &mut NttGlweExternalProductWorkspaceRefMut<'_, T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        S: Data<Elem = T>,
    {
        let size = workspace.size();
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
                workspace.adjusted_poly,
                workspace.carries,
            );
            for (decomposer, key_glwe) in
                basis.decomposer_iter().zip(key_row.iter_ntt_glwe(glwe_len))
            {
                decomposer.decompose_slice_to(
                    workspace.adjusted_poly,
                    workspace.decomposed_ntt,
                    workspace.carries,
                );
                ntt.transform_slice(workspace.decomposed_ntt);
                let digit = NttPolynomial::new(&*workspace.decomposed_ntt);
                workspace
                    .ntt_accumulator
                    .add_mul_ntt_polynomial_assign(&key_glwe, &digit, modulus);
            }
        }
    }
}

#[cfg(feature = "rns")]
impl<S, T> CrtGlwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Multiplies this CRT GLWE by a DCRT GGSW ciphertext, storing the output into `output`.
    ///
    /// # Correctness
    ///
    /// `basis` must match the ordered `rns_base`, and its radix must be
    /// smaller than every RNS modulus for the fast centered digit lift.
    ///
    /// Let `size = workspace.size()`, `N = table.poly_length()`,
    /// `m = rns_base.moduli_count()`, and `w = rns_base.big_uint_value_len()`.
    /// The bound size must match `N`, `m`, the GLWE dimension, and
    /// `basis.decompose_length()`; `workspace.is_compatible(size, rns_base)`
    /// must hold. The table uses the base's modulus order and the gadget
    /// uses its evaluation order and `basis.decomposer_iter()` level order.
    /// CRT/DCRT values must be canonical residues.
    /// Input and output each have `size.rns_glwe_size().rns_glwe_len()`
    /// elements, and the gadget has `size.rns_ggsw_len()` evaluations in
    /// row/level/component/modulus order under a compatible key. Output is
    /// cleared before accumulation; scratch needs no manual reset.
    pub fn mul_dcrt_ggsw_to<M, Table, A, B>(
        &self,
        dcrt_ggsw: &DcrtGgsw<A>,
        output: &mut DcrtGlwe<B>,
        basis: &BigUintApproxSignedBasis<T>,
        table: &DcrtTable<Table>,
        rns_base: &RNSBase<T, M>,
        workspace: &mut DcrtGlevMulWorkspace<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        let crt_poly_len = table.crt_poly_length();
        let dcrt_glev_len = basis.decompose_length() * self.as_ref().len();

        output.set_zero();

        dcrt_ggsw
            .iter_dcrt_glev(dcrt_glev_len)
            .zip(self.iter_crt_poly(crt_poly_len))
            .for_each(|(dcrt_glev, crt_poly)| {
                output.add_dcrt_glev_mul_crt_polynomial_assign(
                    &dcrt_glev, &crt_poly, basis, table, rns_base, workspace,
                );
            });
    }
}
