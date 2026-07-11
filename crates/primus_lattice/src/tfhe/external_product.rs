//! TFHE external product in the Fourier domain.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_poly::FourierPolynomial;

use crate::{
    context::tfhe::TfheFftContext, ggsw::fourier::FourierGgsw, glwe::fourier::FourierGlwe,
    tfhe::TorusGlwe,
};

/// Computes `output = input external_product key`.
pub fn external_product_to<T, Table, A, B, C>(
    input: &TorusGlwe<A>,
    key: &FourierGgsw<B>,
    output: &mut TorusGlwe<C>,
    basis: &ApproxSignedBasis<T>,
    fft: &Table,
    context: &mut TfheFftContext<T>,
    glwe_dimension: usize,
) where
    T: TorusFftValue,
    Table: FftTable,
    A: RawData<Elem = T> + Data,
    B: RawData<Elem = Complex64> + Data,
    C: RawData<Elem = T> + DataMut,
{
    let poly_len = fft.poly_length();
    let fourier_len = fft.fourier_length();
    let level = basis.decompose_length();
    let component_count = glwe_dimension + 1;
    context.fourier_accumulator.fill(Complex64::default());
    let glwe_fourier_len = component_count * fourier_len;
    let glev_len = level * glwe_fourier_len;

    let mut accumulator = FourierGlwe::new(context.fourier_accumulator.as_mut_slice());

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
            accumulator.add_mul_fourier_poly_assign(
                &FourierPolynomial::new(context.decomposed_fourier.as_slice()),
                &key_glwe,
            );
        }
    }

    for (accumulator, result) in context
        .fourier_accumulator
        .chunks_exact(fourier_len)
        .zip(output.as_mut().chunks_exact_mut(poly_len))
    {
        fft.backward_as_torus(accumulator, result);
    }
}
