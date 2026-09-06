//! NGSW external products in the Fourier and NTT domains.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{
    context::{FourierNtruExternalProductContext, NttNtruExternalProductContext},
    nlev::Nlev,
    ntru::Ntru,
    ntru::gadget_product::{accumulate_fourier_gadget_product, accumulate_ntt_gadget_product},
};

use super::{FourierNgsw, NttNgsw};

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
    /// Let `N = context.poly_length()` and `L = basis.decompose_length()`.
    /// The input and output each contain exactly `N` coefficients.
    /// `self` contains exactly `L * N / 2` complex values, grouped
    /// by level in `basis.decomposer_iter()` order. The basis must be the
    /// one used to construct the gadget ciphertext. The input and NGSW
    /// control must use compatible NTRU keys.
    /// `basis` must use the implicit native modulus (`basis.modulus() == None`).
    /// The FFT engine must have polynomial length `N` and Fourier length
    /// `N / 2`; gadget values must use its packing and normalized torus scale.
    /// Output is overwritten and context scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, Table, A, C>(
        &self,
        input: &Ntru<A>,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        debug_assert_eq!(output.as_ref().len(), context.poly_length());
        context.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(self.as_ref(), input.as_ref(), basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
    }

    /// Applies this NGSW external product to every NTRU level in `input`.
    ///
    /// If `input` encrypts `alpha` as NLev and `self` encrypts `beta` as
    /// NGSW, `output` encrypts `alpha * beta` as NLev.
    ///
    /// # Correctness
    ///
    /// The gadget, basis, table, and context must satisfy
    /// [`Self::external_product_to`]. Input and output each have exactly
    /// `basis.decompose_length() * context.poly_length()` coefficient values,
    /// in matching NLev level order under compatible keys. This implementation
    /// requires the NLev and NGSW decomposition lengths to agree. Each output
    /// level is overwritten; context scratch needs no manual reset.
    pub fn external_product_nlev_to<T, Table, A, C>(
        &self,
        input: &Nlev<A>,
        output: &mut Nlev<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let poly_length = context.poly_length();
        let nlev_length = basis.decompose_length() * poly_length;
        debug_assert_eq!(input.as_ref().len(), nlev_length);
        debug_assert_eq!(output.as_ref().len(), nlev_length);

        for (input_level, mut output_level) in input
            .iter_ntru(poly_length)
            .zip(output.iter_ntru_mut(poly_length))
        {
            context.fourier_accumulator.set_zero();
            accumulate_fourier_gadget_product(
                self.as_ref(),
                input_level.as_ref(),
                basis,
                fft,
                context,
            );
            context
                .fourier_accumulator
                .write_torus_form(&mut output_level, fft);
        }
    }
}

impl<S> NttNgsw<S>
where
    S: RawData,
    S::Elem: FheUint,
{
    /// Computes `output = input external_product self` modulo `modulus`.
    ///
    /// `input` and `output` are coefficient-domain scalar NTRU ciphertexts.
    /// `basis` must be the decomposition basis used to construct this NGSW
    /// ciphertext.
    ///
    /// # Correctness
    ///
    /// Let `N = context.poly_length()` and `L = basis.decompose_length()`.
    /// The input and output each contain exactly `N` coefficients.
    /// `self` contains exactly `L * N` evaluations, grouped
    /// by level in `basis.decomposer_iter()` order. The basis must be the
    /// one used to construct the gadget ciphertext. The input and NGSW
    /// control must use compatible NTRU keys.
    /// `basis`, `modulus`, and the NTT table must use the same modulus.
    /// The NTT polynomial length must be `N`, and gadget evaluations must
    /// use that table's order. Input and gadget values must be canonical residues.
    /// Output is overwritten and context scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, M, Table, A, C>(
        &self,
        input: &Ntru<A>,
        output: &mut Ntru<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        S: Data<Elem = T>,
    {
        debug_assert_eq!(output.as_ref().len(), context.poly_length());
        context.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(self.as_ref(), input.as_ref(), basis, modulus, ntt, context);
        context.ntt_accumulator.write_coeff_form(output, ntt);
    }

    /// Applies this NGSW external product to every NTRU level in `input`.
    ///
    /// If `input` encrypts `alpha` as NLev and `self` encrypts `beta` as
    /// NGSW, `output` encrypts `alpha * beta` as NLev.
    ///
    /// # Correctness
    ///
    /// The gadget, basis, table, and context must satisfy
    /// [`Self::external_product_to`]. Input and output each have exactly
    /// `basis.decompose_length() * context.poly_length()` coefficient values,
    /// in matching NLev level order under compatible keys. This implementation
    /// requires the NLev and NGSW decomposition lengths to agree. Each output
    /// level is overwritten; context scratch needs no manual reset.
    pub fn external_product_nlev_to<T, M, Table, A, C>(
        &self,
        input: &Nlev<A>,
        output: &mut Nlev<C>,
        basis: &ApproxSignedBasis<T>,
        modulus: M,
        ntt: &Table,
        context: &mut NttNtruExternalProductContext<T>,
    ) where
        T: FheUint,
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        C: DataMut<Elem = T>,
        S: Data<Elem = T>,
    {
        let poly_length = context.poly_length();
        let nlev_length = basis.decompose_length() * poly_length;
        debug_assert_eq!(input.as_ref().len(), nlev_length);
        debug_assert_eq!(output.as_ref().len(), nlev_length);

        for (input_level, mut output_level) in input
            .iter_ntru(poly_length)
            .zip(output.iter_ntru_mut(poly_length))
        {
            context.ntt_accumulator.set_zero();
            accumulate_ntt_gadget_product(
                self.as_ref(),
                input_level.as_ref(),
                basis,
                modulus,
                ntt,
                context,
            );
            context
                .ntt_accumulator
                .write_coeff_form(&mut output_level, ntt);
        }
    }
}
