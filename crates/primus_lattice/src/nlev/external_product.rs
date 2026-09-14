//! NLev external products using the shared scalar NTRU gadget kernels.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::FieldContext;

use crate::{
    context::{FourierNtruExternalProductContext, NttNtruExternalProductContext},
    ntru::{
        FourierNtru, Ntru, NttNtru,
        gadget_product::{accumulate_fourier_gadget_product, accumulate_ntt_gadget_product},
    },
};

use super::{FourierNlev, NttNlev};

impl<S> FourierNlev<S>
where
    S: Data<Elem = Complex64>,
{
    /// Computes the gadget external product `polynomial odot self`.
    ///
    /// The output is a coefficient-domain scalar NTRU ciphertext. `basis`
    /// must be the decomposition basis used to construct this NLev ciphertext.
    ///
    /// # Correctness
    ///
    /// Let `N = context.poly_length()` and `L = basis.decompose_length()`.
    /// The polynomial input and output each contain exactly `N` coefficients.
    /// `self` contains exactly `L * N / 2` complex values, grouped
    /// by level in `basis.decomposer_iter()` order. The basis must be the
    /// one used to construct the gadget ciphertext.
    /// `basis` must use the implicit native modulus (`basis.modulus() == None`).
    /// The FFT engine must have polynomial length `N` and Fourier length
    /// `N / 2`; gadget values must use its packing and normalized torus scale.
    /// Output is overwritten and context scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    pub fn external_product_to<T, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
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
        let mut context = context.as_mut();
        context.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            fft,
            &mut context,
        );
        context.fourier_accumulator.write_torus_form(output, fft);
    }

    /// Computes the gadget product directly in this key's Fourier representation.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::external_product_to`]'s input, key, basis, table and
    /// workspace contracts. Output contains exactly `N / 2` complex values at
    /// torus scale. It is used directly as the accumulator, without an inverse
    /// transform or torus rounding; later conversion requires the same FFT table.
    ///
    /// # Panics
    /// Panics if the output length is not `context.poly_length() / 2`.
    pub fn external_product_fourier_to<T, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
        output: &mut FourierNtru<C>,
        basis: &ApproxSignedBasis<T>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut FourierNtruExternalProductContext<T>,
    ) where
        T: TorusFftValue,
        Table: FftTable,
        A: Data<Elem = T>,
        C: DataMut<Elem = Complex64>,
    {
        assert_eq!(
            output.as_ref().len(),
            context.poly_length() / 2,
            "external-product output length mismatch"
        );
        let mut context = context.as_mut_with_accumulator(output);
        context.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            fft,
            &mut context,
        );
    }
}

impl<S> NttNlev<S>
where
    S: RawData,
    S::Elem: FheUint,
{
    /// Computes the gadget external product `polynomial odot self`.
    ///
    /// The output is a coefficient-domain scalar NTRU ciphertext. `basis`
    /// must be the decomposition basis used to construct this NLev ciphertext.
    ///
    /// # Correctness
    ///
    /// Let `N = context.poly_length()` and `L = basis.decompose_length()`.
    /// The polynomial input and output each contain exactly `N` coefficients.
    /// `self` contains exactly `L * N` evaluations, grouped
    /// by level in `basis.decomposer_iter()` order. The basis must be the
    /// one used to construct the gadget ciphertext.
    /// `basis`, `modulus`, and the NTT table must use the same modulus.
    /// The NTT polynomial length must be `N`, and gadget evaluations must
    /// use that table's order. Input and gadget values must be canonical residues.
    /// Output is overwritten and context scratch is initialized as needed;
    /// no manual reset is required. Context dimensions do not validate the
    /// basis, key, table, or actual ciphertext buffers.
    ///
    /// # Panics
    /// Panics before output writes if its length is not `context.poly_length()`.
    pub fn external_product_to<T, M, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
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
        // Coefficients and NTT evaluations share storage. Accumulate into the
        // destination, then invert in place to avoid copying an entire polynomial.
        assert_eq!(
            output.as_ref().len(),
            context.poly_length(),
            "external-product output length mismatch"
        );
        let mut transformed = NttNtru(output.as_mut());
        let mut context = context.as_mut_with_accumulator(&mut transformed);
        context.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            modulus,
            ntt,
            &mut context,
        );
        ntt.inverse_transform_slice(context.ntt_accumulator.as_mut());
    }

    /// Computes the gadget product directly in this key's NTT representation.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::external_product_to`]'s input, key, basis, table and
    /// workspace contracts. Output contains exactly `N` canonical evaluations
    /// in the table's order. It is used directly as the accumulator, without a copy
    /// from the context or an inverse transform.
    ///
    /// # Panics
    /// Panics if the output length is not `context.poly_length()`.
    pub fn external_product_ntt_to<T, M, Table, A, C>(
        &self,
        polynomial: &Polynomial<A>,
        output: &mut NttNtru<C>,
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
        assert_eq!(
            output.as_ref().len(),
            context.poly_length(),
            "external-product output length mismatch"
        );
        let mut context = context.as_mut_with_accumulator(output);
        context.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            modulus,
            ntt,
            &mut context,
        );
    }
}
