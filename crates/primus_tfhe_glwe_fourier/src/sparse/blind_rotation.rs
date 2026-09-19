//! Sparse blind rotation: native coefficient aggregation, FFT, external product.

use primus_data::{Data, DataMut};
use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::{
    context::FourierGlweExternalProductContext,
    ggsw::{FourierGgsw, Ggsw},
    glwe::TorusGlwe,
    lwe::Lwe,
};
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationQuantizer;

use super::SparseGlweBootstrappingKey;

impl<T: TorusFftValue> SparseGlweBootstrappingKey<T> {
    /// Blind-rotates an encoded LUT into a native coefficient GLWE ciphertext.
    ///
    /// Uses ordinary PBS quantization (rotation step one), initializing a trivial
    /// accumulator with `X^(-R(b)) * LUT`. Each bucket's control encrypts its
    /// selected `X^R(a[i])`, or `1` if unoccupied. All encrypted zero entries and
    /// dummies contribute to the control's noise; none are skipped.
    /// The output is overwritten and scratch is reused without online allocation.
    ///
    /// # Correctness
    ///
    /// Input must use this key's small-LWE secret. The LUT contains `N` encoded
    /// native-torus coefficients with sufficient input and output noise margins.
    /// This raw operation performs neither key switching nor sample extraction.
    /// Coefficient aggregation is exact modulo `2^T::BITS`; conversion to Fourier
    /// form and external products add floating-point rounding error.
    ///
    /// # Panics
    ///
    /// Panics if input, LUT, output, workspace or FFT polynomial lengths do not
    /// match this key. Checks precede output writes.
    pub fn fourier_blind_rotate_lookup_table_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut SparseGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        self.fourier_blind_rotate_interleaved_lookup_table_to(
            input,
            lookup_table,
            1,
            output,
            fft,
            context,
        );
    }

    /// Blind-rotates an interleaved LUT, preserving its output columns.
    ///
    /// Quantizes every mask and body coefficient to `2N / rotation_step`, then
    /// multiplies by `rotation_step`. This must be the LUT's padded output count:
    /// a nonzero power of two dividing `N`.
    /// Inherits [`Self::fourier_blind_rotate_lookup_table_to`]'s requirements.
    /// An invalid rotation step also panics before output writes.
    pub fn fourier_blind_rotate_interleaved_lookup_table_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        rotation_step: usize,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut SparseGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let size = self.size();
        let poly_length = size.glwe_size().poly_length();
        assert!(
            rotation_step.is_power_of_two() && poly_length.is_multiple_of(rotation_step),
            "PBSManyLUT rotation step must be a non-zero power-of-two divisor of N"
        );
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len(),
            ),
            (self.input_dimension(), poly_length, size.glwe_len()),
            "sparse blind-rotation input, LUT or output layout mismatch"
        );
        assert_eq!(
            (
                context.input_exponents.len(),
                context.external_product.size()
            ),
            (self.input_dimension(), size),
            "sparse blind-rotation workspace layout mismatch"
        );
        assert_eq!(
            fft.poly_length(),
            poly_length,
            "sparse blind-rotation FFT length mismatch"
        );
        self.fourier_blind_rotate_interleaved_lookup_table_kernel_to(
            input,
            lookup_table,
            rotation_step,
            output,
            fft,
            context,
        );
    }

    /// The public raw wrapper or evaluator has checked layouts, FFT and LUT.
    /// Mask and body use the same step so every rotation preserves output slots.
    pub(crate) fn fourier_blind_rotate_interleaved_lookup_table_kernel_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        rotation_step: usize,
        output: &mut TorusGlwe<C>,
        fft: &mut FftEngine<'_, Table>,
        context: &mut SparseGlweBlindRotationContext<T>,
    ) where
        Table: FftTable,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let size = self.size();
        let poly_length = size.glwe_size().poly_length();
        let modulus = self.input_modulus();
        let SparseGlweBlindRotationContext {
            input_exponents,
            aggregate,
            transformed,
            scratch,
            external_product,
        } = context;
        let quantizer = if rotation_step == 1 {
            self.input_quantizer()
        } else {
            RotationQuantizer::new(modulus, 2 * poly_length, rotation_step)
        };
        quantizer.exponent_slice_to(input.a(), input_exponents);
        let initial_exponent = quantizer.exponent(input.b()).wrapping_neg() & (2 * poly_length - 1);
        let (mask, body) = output.a_b_mut_slices(poly_length);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(initial_exponent, &mut Polynomial(body), modulus);

        let mut output_is_current = true;
        for bucket_index in 0..self.bucket_count() {
            let (indices, ciphertexts) = self.bucket_data(bucket_index);
            let (selections, dummy) = ciphertexts.split_at(indices.len() * size.ggsw_len());
            // A bucket always has one dummy, including publicly empty buckets.
            // Start from it so no aggregation state survives the previous bucket.
            aggregate.as_mut().copy_from_slice(dummy);
            for (&input_index, selection) in
                indices.iter().zip(selections.chunks_exact(size.ggsw_len()))
            {
                let exponent = input_exponents[input_index];
                for (acc, source) in aggregate
                    .as_mut()
                    .chunks_exact_mut(poly_length)
                    .zip(selection.chunks_exact(poly_length))
                {
                    Polynomial(acc).add_mul_monomial_assign(&Polynomial(source), exponent, modulus);
                }
            }
            // Transform only the completed aggregate. Native wrapping above is
            // exact; each polynomial is lifted at the normalized torus scale.
            aggregate.write_fourier_form(transformed, fft);
            if output_is_current {
                transformed.external_product_to(
                    output,
                    scratch,
                    self.basis(),
                    fft,
                    external_product,
                );
            } else {
                transformed.external_product_to(
                    scratch,
                    output,
                    self.basis(),
                    fft,
                    external_product,
                );
            }
            output_is_current = !output_is_current;
        }
        if !output_is_current {
            output.as_mut().copy_from_slice(scratch.as_ref());
        }
    }
}

/// Reusable workspace for Fourier [`SparseGlweBootstrappingKey`] blind rotation.
///
/// Stores public input exponents, coefficient and Fourier aggregate buffers,
/// one coefficient GLWE buffer and external-product scratch. It contains no
/// plaintext secret support or matching, and allocates only during construction.
pub struct SparseGlweBlindRotationContext<T: TorusFftValue> {
    input_exponents: Vec<usize>,
    aggregate: Ggsw<Vec<T>>,
    transformed: FourierGgsw<Vec<Complex64>>,
    scratch: TorusGlwe<Vec<T>>,
    external_product: FourierGlweExternalProductContext<T>,
}

impl<T: TorusFftValue> SparseGlweBlindRotationContext<T> {
    /// Allocates scratch for this key's input dimension and gadget layout.
    /// Reusable with other sparse keys of the same dimensions and layout.
    #[must_use]
    pub fn new(key: &SparseGlweBootstrappingKey<T>) -> Self {
        let size = key.size();
        Self {
            input_exponents: vec![0; key.input_dimension()],
            aggregate: Ggsw::zero(size.ggsw_len()),
            transformed: FourierGgsw::zero(size.fourier_ggsw_len()),
            scratch: TorusGlwe::zero(size.glwe_len()),
            external_product: FourierGlweExternalProductContext::new(size),
        }
    }
}
