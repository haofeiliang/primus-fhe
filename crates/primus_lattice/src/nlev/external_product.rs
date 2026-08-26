//! NLev external products and shared NTRU gadget-product kernels.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial, Polynomial};
use primus_reduce::FieldContext;

use crate::{
    context::{FourierNtruExternalProductContext, NttNtruExternalProductContext},
    ntru::Ntru,
};

use super::{FourierNlev, NttNlev};

/// Clears the Fourier accumulator, then stores the gadget product of `gadget` and `input` in it.
pub(crate) fn fourier_gadget_product_to_accumulator<T, Table>(
    gadget: &[Complex64],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    context: &mut FourierNtruExternalProductContext<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    context.fourier_accumulator.set_zero();
    fourier_gadget_product_add_assign(gadget, input, basis, fft, context);
}

/// Adds the gadget product of `gadget` and `input` to the existing Fourier accumulator.
/// This does not clear the accumulator; the caller must initialize it first.
pub(crate) fn fourier_gadget_product_add_assign<T, Table>(
    gadget: &[Complex64],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    context: &mut FourierNtruExternalProductContext<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
{
    let poly_length = context.poly_length();
    let fourier_length = fft.fourier_length();

    debug_assert_eq!(fft.poly_length(), poly_length);
    debug_assert_eq!(fourier_length, poly_length / 2);
    debug_assert_eq!(basis.modulus(), None);
    debug_assert_eq!(input.len(), poly_length);
    debug_assert_eq!(gadget.len(), basis.decompose_length() * fourier_length);

    basis.init_carry_slice(input, &mut context.carries);

    for (decomposer, key_level) in basis
        .decompose_iter()
        .zip(gadget.chunks_exact(fourier_length))
    {
        decomposer.decompose_slice_to(input, &mut context.decomposed_poly, &mut context.carries);
        fft.forward_as_integer(&context.decomposed_poly, &mut context.decomposed_fourier);
        FourierPolynomial(context.fourier_accumulator.as_mut()).add_mul_assign(
            &FourierPolynomial(context.decomposed_fourier.as_slice()),
            &FourierPolynomial(key_level),
        );
    }
}

/// Clears the NTT accumulator, then stores the gadget product of `gadget` and `input` in it.
pub(crate) fn ntt_gadget_product_to_accumulator<T, M, Table>(
    gadget: &[T],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    ntt: &Table,
    context: &mut NttNtruExternalProductContext<T>,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    context.ntt_accumulator.set_zero();
    ntt_gadget_product_add_assign(gadget, input, basis, modulus, ntt, context);
}

/// Adds the gadget product of `gadget` and `input` to the existing NTT accumulator.
/// This does not clear the accumulator; the caller must initialize it first.
pub(crate) fn ntt_gadget_product_add_assign<T, M, Table>(
    gadget: &[T],
    input: &[T],
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    ntt: &Table,
    context: &mut NttNtruExternalProductContext<T>,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
{
    let poly_length = context.poly_length();

    debug_assert_eq!(ntt.poly_length(), poly_length);
    debug_assert_eq!(ntt.modulus(), modulus.value());
    debug_assert_eq!(basis.modulus(), Some(modulus.value()));
    debug_assert_eq!(input.len(), poly_length);
    debug_assert_eq!(gadget.len(), basis.decompose_length() * poly_length);

    basis.init_value_carry_slice_to(input, &mut context.adjusted_poly, &mut context.carries);

    for (decomposer, key_level) in basis.decompose_iter().zip(gadget.chunks_exact(poly_length)) {
        decomposer.decompose_slice_to(
            &context.adjusted_poly,
            &mut context.decomposed_ntt,
            &mut context.carries,
        );
        ntt.transform_slice(&mut context.decomposed_ntt);
        NttPolynomial(context.ntt_accumulator.as_mut()).add_mul_assign(
            &NttPolynomial(key_level),
            &NttPolynomial(context.decomposed_ntt.as_slice()),
            modulus,
        );
    }
}

impl<S> FourierNlev<S>
where
    S: RawData<Elem = Complex64>,
{
    /// Computes the gadget external product `polynomial odot self`.
    ///
    /// The result is a coefficient-domain scalar NTRU ciphertext. `basis`
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
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
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
    /// The result is a coefficient-domain scalar NTRU ciphertext. `basis`
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
        A: RawData<Elem = T> + Data,
        C: RawData<Elem = T> + DataMut,
        S: RawData<Elem = T> + Data,
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
