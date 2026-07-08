//! TFHE external product in the Fourier domain.
//!
//! The external product multiplies a coefficient GLWE ciphertext by a
//! Fourier-domain GGSW key using signed gadget decomposition, accumulation
//! in the Fourier domain, and inverse FFT back to the coefficient domain.
//!
//! All Fourier buffers use split `[re | im]` f64 layout.

use primus_data::{Data, DataMut, RawData};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, TorusFftValue};
use primus_poly::FourierPolynomial;

use crate::context::tfhe::TfheFftContext;
use crate::ggsw::fourier::FourierGgsw;
use crate::tfhe::TorusGlwe;

/// TFHE external product: `output = input ⊡ key` in the Fourier domain.
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
    B: RawData<Elem = f64> + Data,
    C: RawData<Elem = T> + DataMut,
{
    let poly_len = fft.poly_length();
    let blen = fft.buffer_len(); // 2 * fourier_length
    let level = basis.decompose_length();
    let total_components = glwe_dimension + 1;

    // Zero the accumulator (split f64).
    context.fourier_accumulator.fill(0.0);

    // Key layout: (k+1) rows × level GLWE × (k+1) polynomials.
    let glwe_fourier_len = total_components * blen;
    let glev_len = level * glwe_fourier_len;

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

            // Forward FFT → split f64 (directly into decomposed_fourier).
            fft.forward_torus_slice(&context.decomposed_poly, &mut context.decomposed_fourier);
            let decomposed = FourierPolynomial::new(context.decomposed_fourier.as_slice());

            // accumulator += decomposed * key_glwe (component-wise).
            for out_idx in 0..total_components {
                let acc_start = out_idx * blen;
                let acc_end = acc_start + blen;
                let key_start = out_idx * blen;
                let key_end = key_start + blen;

                let mut acc =
                    FourierPolynomial::new(&mut context.fourier_accumulator[acc_start..acc_end]);
                let key_poly = FourierPolynomial::new(&key_glwe.as_ref()[key_start..key_end]);

                acc.add_mul_assign(&decomposed, &key_poly);
            }
        }
    }

    // Inverse FFT: split f64 accumulator → torus output.
    for out_idx in 0..total_components {
        let acc_start = out_idx * blen;
        let acc_end = acc_start + blen;
        let out_start = out_idx * poly_len;
        let out_end = out_start + poly_len;
        fft.inverse_torus_slice(
            &context.fourier_accumulator[acc_start..acc_end],
            &mut output.as_mut()[out_start..out_end],
        );
    }
}
