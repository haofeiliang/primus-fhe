//! NLev external products and shared NTRU gadget-product kernels.

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
        gadget_product::{
            fourier_gadget_product_to_accumulator, ntt_gadget_product_to_accumulator,
        },
    },
};

use super::{FourierNlev, NttNlev};

impl<S> FourierNlev<S>
where
    S: RawData<Elem = Complex64>,
{
    /// Computes the gadget external product `polynomial odot self`.
    ///
    /// The output is a coefficient-domain scalar NTRU ciphertext. `basis`
    /// must be the decomposition basis used to construct this NLev ciphertext.
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
        S: Data,
    {
        debug_assert_eq!(output.as_ref().len(), context.poly_length());
        fourier_gadget_product_to_accumulator(
            self.as_ref(),
            polynomial.as_ref(),
            basis,
            fft,
            context,
        );
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
        ntt_gadget_product_to_accumulator(
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
