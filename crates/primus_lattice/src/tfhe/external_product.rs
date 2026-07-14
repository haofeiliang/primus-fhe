//! TFHE external products in the Fourier and NTT domains.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_poly::{FourierPolynomial, NttPolynomial};
use primus_reduce::FieldContext;

use crate::{
    context::tfhe::{TfheFftContext, TfheNttContext},
    ggsw::{FourierGgsw, NttGgsw},
    glwe::{Glwe, TorusGlwe},
};

/// Computes `output = input external_product key` with a Fourier GGSW key.
///
/// This operation uses the implicit native torus modulus. `input` and
/// `output` are coefficient-domain torus GLWE ciphertexts. The context binds
/// the validated layout; `basis` must be the decomposition basis used by
/// `key`.
pub fn fourier_external_product_to<T, Table, A, B, C>(
    input: &TorusGlwe<A>,
    key: &FourierGgsw<B>,
    output: &mut TorusGlwe<C>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    context: &mut TfheFftContext<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: RawData<Elem = T> + Data,
    B: RawData<Elem = Complex64> + Data,
    C: RawData<Elem = T> + DataMut,
{
    debug_assert_eq!(output.as_ref().len(), context.size().glwe_len());
    fourier_external_product_accumulate(input, key, basis, fft, context);
    context.fourier_accumulator.write_torus_form(output, fft);
}

pub(super) fn fourier_external_product_accumulate<T, Table, A, B>(
    input: &TorusGlwe<A>,
    key: &FourierGgsw<B>,
    basis: &ApproxSignedBasis<T>,
    fft: &mut FftEngine<'_, Table>,
    context: &mut TfheFftContext<T>,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: RawData<Elem = T> + Data,
    B: RawData<Elem = Complex64> + Data,
{
    let size = context.size();
    let poly_len = size.poly_length();
    let fourier_len = poly_len / 2;
    let glwe_fourier_len = size.fourier_glwe_len();
    let glev_len = basis.decompose_length() * glwe_fourier_len;

    debug_assert_eq!(fft.poly_length(), poly_len);
    debug_assert_eq!(fft.fourier_length(), fourier_len);
    debug_assert_eq!(basis.modulus(), None);
    debug_assert_eq!(input.as_ref().len(), size.glwe_len());
    debug_assert_eq!(key.as_ref().len(), size.component_count() * glev_len);
    debug_assert_eq!(context.carries.len(), poly_len);
    debug_assert_eq!(context.decomposed_poly.len(), poly_len);
    debug_assert_eq!(context.decomposed_fourier.len(), fourier_len);
    debug_assert_eq!(context.fourier_accumulator.0.len(), glwe_fourier_len);

    context.fourier_accumulator.set_zero();

    for (coeff_poly, key_row) in input.iter_poly(poly_len).zip(key.iter_glev(glev_len)) {
        basis.init_carry_slice(coeff_poly.0, &mut context.carries);
        for (decomposer, key_glwe) in basis
            .decompose_iter()
            .zip(key_row.iter_glwe(glwe_fourier_len))
        {
            decomposer.decompose_slice_to(
                coeff_poly.0,
                &mut context.decomposed_poly,
                &mut context.carries,
            );
            fft.forward_as_integer(&context.decomposed_poly, &mut context.decomposed_fourier);
            context.fourier_accumulator.add_mul_fourier_poly_assign(
                &FourierPolynomial::new(context.decomposed_fourier.as_slice()),
                &key_glwe,
            );
        }
    }
}

/// Computes `output = input external_product key` with an NTT GGSW key.
///
/// The input and output are coefficient-domain GLWE ciphertexts with every
/// coefficient reduced to `[0, q)`. The context binds the validated layout;
/// `basis` and `modulus` must match those used by `key`.
pub fn ntt_external_product_to<T, M, Table, A, B, C>(
    input: &Glwe<A>,
    key: &NttGgsw<B>,
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
    debug_assert_eq!(output.as_ref().len(), context.size().glwe_len());
    ntt_external_product_accumulate(input, key, basis, modulus, ntt, context);
    context.ntt_accumulator.write_coeff_form(output, ntt);
}

pub(super) fn ntt_external_product_accumulate<T, M, Table, A, B>(
    input: &Glwe<A>,
    key: &NttGgsw<B>,
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
{
    let size = context.size();
    let poly_len = size.poly_length();
    let glwe_len = size.glwe_len();
    let glev_len = basis.decompose_length() * glwe_len;

    debug_assert_eq!(ntt.poly_length(), poly_len);
    debug_assert_eq!(basis.modulus(), modulus.value());
    debug_assert!(modulus.value().is_some());
    debug_assert_eq!(input.as_ref().len(), glwe_len);
    debug_assert_eq!(key.as_ref().len(), size.component_count() * glev_len);
    debug_assert_eq!(context.adjusted_poly.len(), poly_len);
    debug_assert_eq!(context.carries.len(), poly_len);
    debug_assert_eq!(context.decomposed_ntt.len(), poly_len);
    debug_assert_eq!(context.ntt_accumulator.as_ref().len(), glwe_len);

    context.ntt_accumulator.set_zero();

    for (coeff_poly, key_row) in input.iter_poly(poly_len).zip(key.iter_ntt_glev(glev_len)) {
        basis.init_value_carry_slice_to(
            coeff_poly.as_ref(),
            &mut context.adjusted_poly,
            &mut context.carries,
        );
        for (decomposer, key_glwe) in basis.decompose_iter().zip(key_row.iter_ntt_glwe(glwe_len)) {
            decomposer.decompose_slice_to(
                &context.adjusted_poly,
                &mut context.decomposed_ntt,
                &mut context.carries,
            );
            ntt.transform_slice(&mut context.decomposed_ntt);
            let digit = NttPolynomial::new(context.decomposed_ntt.as_slice());
            context
                .ntt_accumulator
                .add_mul_ntt_polynomial_assign(&digit, &key_glwe, modulus);
        }
    }
}
