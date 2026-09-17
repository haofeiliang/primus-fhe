//! Reference sparse blind rotation: coefficient aggregation, NTT, external product.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{context::NttGlweExternalProductContext, ggsw::Ggsw, glwe::Glwe, lwe::Lwe};
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_tfhe::rotation::RotationQuantizer;

use super::SparseGlweBootstrappingKey;

impl<T: FheUint> SparseGlweBootstrappingKey<T> {
    /// Blind-rotates an encoded LUT into a coefficient-domain GLWE ciphertext.
    ///
    /// Uses ordinary PBS quantization (rotation step one). Quantizes each input
    /// coefficient once to `2N`, initializes a trivial
    /// accumulator with `X^(-R(b)) * LUT`, then applies one external product per
    /// bucket. Its control encrypts the selected `X^R(a[i])`, or `1` if no entry
    /// is selected. All buckets and encrypted zero entries are processed.
    /// The caller owns the output; `context` is reused without online allocation.
    ///
    /// # Correctness
    ///
    /// The input must use this key's small-LWE secret. Input and LUT coefficients
    /// must be canonical under [`Self::input_modulus`]. The LUT has `N` encoded
    /// coefficients; the caller is responsible for its encoding and noise margin.
    /// This raw operation performs neither key switching nor sample extraction.
    ///
    /// # Panics
    ///
    /// Panics if input, LUT, output or workspace layouts, or the NTT length/modulus
    /// do not match this key. These checks precede output writes.
    pub fn ntt_blind_rotate_lookup_table_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut Glwe<C>,
        ntt: &Table,
        context: &mut SparseGlweBlindRotationContext<T>,
    ) where
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let size = self.size();
        let poly_length = size.glwe_size().poly_length();
        let modulus = self.input_modulus();
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len()
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
            ntt.poly_length(),
            poly_length,
            "sparse blind-rotation NTT length mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "sparse blind-rotation NTT modulus mismatch"
        );

        self.ntt_blind_rotate_interleaved_lookup_table_kernel_to(
            input,
            lookup_table,
            1,
            output,
            ntt,
            context,
        );
    }

    /// The public raw wrapper or evaluator has checked layouts, table and LUT.
    /// The rotation step is the compiled LUT's padded output count; every mask
    /// and body coefficient must use this same step to preserve output slots.
    pub(crate) fn ntt_blind_rotate_interleaved_lookup_table_kernel_to<Table, A, B, C>(
        &self,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        rotation_step: usize,
        output: &mut Glwe<C>,
        ntt: &Table,
        context: &mut SparseGlweBlindRotationContext<T>,
    ) where
        Table: NttTable<ValueT = T>,
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

        // Bound the aggregation working set while keeping complete polynomials.
        // Small GGSWs fit in one tile; larger ones reuse each tile across entries.
        let tile_length = (16 * 1024 / size_of::<T>() / poly_length).max(1) * poly_length;
        let mut output_is_current = true;
        for bucket_index in 0..self.bucket_count() {
            let (indices, ciphertexts) = self.bucket_data(bucket_index);
            let (selections, dummy) = ciphertexts.split_at(indices.len() * size.ggsw_len());
            // Every bucket has a dummy, even if publicly empty. It overwrites the
            // previous bucket's NTT values before adding the rotated selections.
            aggregate.copy_from_slice(dummy);
            for (tile_index, tile) in aggregate.chunks_mut(tile_length).enumerate() {
                let start = tile_index * tile_length;
                let end = start + tile.len();
                for (&input_index, selection) in
                    indices.iter().zip(selections.chunks_exact(size.ggsw_len()))
                {
                    let exponent = input_exponents[input_index];
                    for (acc, source) in tile
                        .chunks_exact_mut(poly_length)
                        .zip(selection[start..end].chunks_exact(poly_length))
                    {
                        Polynomial(acc).add_mul_monomial_assign(
                            &Polynomial(source),
                            exponent,
                            modulus,
                        );
                    }
                }
            }
            let aggregate_ntt = Ggsw::new(aggregate.as_mut_slice()).into_ntt_form(ntt);
            if output_is_current {
                aggregate_ntt.external_product_to(
                    output,
                    scratch,
                    self.basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            } else {
                aggregate_ntt.external_product_to(
                    scratch,
                    output,
                    self.basis(),
                    modulus,
                    ntt,
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

/// Reusable workspace for [`SparseGlweBootstrappingKey`] blind rotation.
///
/// Stores input exponents, one aggregate transformed in place, a GLWE buffer and
/// external-product scratch. It contains no secret support or matching data.
pub struct SparseGlweBlindRotationContext<T: FheUint> {
    input_exponents: Vec<usize>,
    aggregate: Vec<T>,
    scratch: Glwe<Vec<T>>,
    external_product: NttGlweExternalProductContext<T>,
}

impl<T: FheUint> SparseGlweBlindRotationContext<T> {
    /// Allocates scratch for the key's input dimension and gadget layout.
    /// It can be reused with other sparse keys of the same dimensions and layout.
    #[must_use]
    pub fn new(key: &SparseGlweBootstrappingKey<T>) -> Self {
        let size = key.size();
        Self {
            input_exponents: vec![0; key.input_dimension()],
            aggregate: vec![T::ZERO; size.ggsw_len()],
            scratch: Glwe::zero(size.glwe_len()),
            external_product: NttGlweExternalProductContext::new(size),
        }
    }
}
