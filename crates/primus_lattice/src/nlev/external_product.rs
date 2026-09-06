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
        Ntru,
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
        context.fourier_accumulator.set_zero();
        accumulate_fourier_gadget_product(self.as_ref(), polynomial.as_ref(), basis, fft, context);
        context.fourier_accumulator.write_torus_form(output, fft);
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
        debug_assert_eq!(output.as_ref().len(), context.poly_length());
        context.ntt_accumulator.set_zero();
        accumulate_ntt_gadget_product(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            modulus,
            ntt,
            context,
        );
        context.ntt_accumulator.write_coeff_form(output, ntt);
    }
}
