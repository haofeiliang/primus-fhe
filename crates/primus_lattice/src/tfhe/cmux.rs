//! TFHE conditional multiplexer in the Fourier and NTT domains.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_modulus::NativeModulus;
use primus_ntt::NttTable;
use primus_reduce::FieldContext;

use crate::{
    context::{TfheFftContext, TfheNttContext},
    ggsw::{FourierGgsw, NttGgsw},
    glwe::{Glwe, TorusGlwe},
};

use super::external_product::{
    fourier_external_product_accumulate, ntt_external_product_accumulate,
};

/// Computes `output = ct0 + control external_product (ct1 - ct0)`.
///
/// `control` is a Fourier GGSW encryption of a bit. A control bit of zero
/// selects `ct0`, while a control bit of one selects `ct1`. The GLWE inputs
/// and output use the implicit native torus modulus and coefficient form.
pub fn fourier_cmux_to<T, Table, A, B, C, D>(
    control: &FourierGgsw<A>,
    ct0: &TorusGlwe<B>,
    ct1: &TorusGlwe<C>,
    output: &mut TorusGlwe<D>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    context: &mut TfheFftContext<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: RawData<Elem = Complex64> + Data,
    B: RawData<Elem = T> + Data,
    C: RawData<Elem = T> + Data,
    D: RawData<Elem = T> + DataMut,
{
    let size = context.size();
    debug_assert_eq!(ct0.as_ref().len(), size.glwe_len());
    debug_assert_eq!(ct1.as_ref().len(), size.glwe_len());
    debug_assert_eq!(output.as_ref().len(), size.glwe_len());

    ct1.sub_element_wise_to(ct0, output, NativeModulus::new());
    fourier_external_product_accumulate(output, control, basis, fft, context);
    context.fourier_accumulator.write_torus_form(output, fft);
    output.add_element_wise_assign(ct0, NativeModulus::new());
}

/// Computes `output = ct0 + control external_product (ct1 - ct0)`.
///
/// `control` is an NTT GGSW encryption of a bit. A control bit of zero selects
/// `ct0`, while a control bit of one selects `ct1`. Every coefficient-domain
/// GLWE coefficient must be reduced to `[0, q)`.
pub fn ntt_cmux_to<T, M, Table, A, B, C, D>(
    control: &NttGgsw<A>,
    ct0: &Glwe<B>,
    ct1: &Glwe<C>,
    output: &mut Glwe<D>,
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    ntt: &Table,
    context: &mut TfheNttContext<T>,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
    A: RawData<Elem = T> + Data,
    B: RawData<Elem = T> + Data,
    C: RawData<Elem = T> + Data,
    D: RawData<Elem = T> + DataMut,
{
    let size = context.size();
    debug_assert_eq!(ct0.as_ref().len(), size.glwe_len());
    debug_assert_eq!(ct1.as_ref().len(), size.glwe_len());
    debug_assert_eq!(output.as_ref().len(), size.glwe_len());

    ct1.sub_element_wise_to(ct0, output, modulus);
    ntt_external_product_accumulate(output, control, basis, modulus, ntt, context);
    context.ntt_accumulator.write_coeff_form(output, ntt);
    output.add_element_wise_assign(ct0, modulus);
}

/// Computes `output = input + control external_product
/// (input * (X^exponent - 1))` for the native-torus Fourier backend.
///
/// This is the CMUX form used by blind rotation. `exponent` must belong to
/// `[0, 2N)`.
pub fn fourier_cmux_monomial_to<T, Table, A, B, C>(
    control: &FourierGgsw<A>,
    input: &TorusGlwe<B>,
    exponent: usize,
    output: &mut TorusGlwe<C>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    context: &mut TfheFftContext<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: RawData<Elem = Complex64> + Data,
    B: RawData<Elem = T> + Data,
    C: RawData<Elem = T> + DataMut,
{
    let poly_length = context.size().poly_length();
    debug_assert!(exponent < 2 * poly_length);

    input.mul_monomial_sub_one_to(exponent, output, poly_length, NativeModulus::new());
    fourier_external_product_accumulate(output, control, basis, fft, context);
    context.fourier_accumulator.write_torus_form(output, fft);
    output.add_element_wise_assign(input, NativeModulus::new());
}

/// Computes `output = input + control external_product
/// (input * (X^exponent - 1))` for the NTT backend.
///
/// This is the CMUX form used by blind rotation. `exponent` must belong to
/// `[0, 2N)`.
pub fn ntt_cmux_monomial_to<T, M, Table, A, B, C>(
    control: &NttGgsw<A>,
    input: &Glwe<B>,
    exponent: usize,
    output: &mut Glwe<C>,
    basis: &ApproxSignedBasis<T>,
    modulus: M,
    ntt: &Table,
    context: &mut TfheNttContext<T>,
) where
    T: FheUint,
    M: FieldContext<T>,
    Table: NttTable<ValueT = T>,
    A: RawData<Elem = T> + Data,
    B: RawData<Elem = T> + Data,
    C: RawData<Elem = T> + DataMut,
{
    let poly_length = context.size().poly_length();
    debug_assert!(exponent < 2 * poly_length);

    input.mul_monomial_sub_one_to(exponent, output, poly_length, modulus);
    ntt_external_product_accumulate(output, control, basis, modulus, ntt, context);
    context.ntt_accumulator.write_coeff_form(output, ntt);
    output.add_element_wise_assign(input, modulus);
}
