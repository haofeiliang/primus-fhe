//! Reference sparse blind rotation: coefficient aggregation, NTT, external product.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{
    ggsw::Ggsw, glwe::Glwe, lwe::Lwe, workspace::NttGlweExternalProductWorkspace,
};
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_reduce::ReduceOnceSlice;
use primus_tfhe::rotation::RotationModulusSwitch;

use super::SparseGlweBootstrappingKey;

/// Reusable workspace for [`SparseGlweBootstrappingKey`] blind rotation.
///
/// Stores input exponents, one aggregate transformed in place, a GLWE buffer and
/// external-product scratch. It contains no secret support or matching data.
pub struct SparseGlweBlindRotationWorkspace<T: FheUint> {
    input_exponents: Vec<usize>,
    aggregate: Vec<T>,
    scratch: Glwe<Vec<T>>,
    external_product: NttGlweExternalProductWorkspace<T>,
}

impl<T: FheUint> SparseGlweBlindRotationWorkspace<T> {
    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut NttGlweExternalProductWorkspace<T>) -> R,
    ) -> R {
        self.external_product.with_rebound(size, operation)
    }

    /// Allocates scratch for the key's input dimension and gadget layout.
    /// It can be reused with other sparse keys of the same dimensions and layout.
    #[must_use]
    pub fn new(key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>) -> Self {
        let size = key.size();
        Self {
            input_exponents: vec![0; key.input_dimension().get()],
            aggregate: vec![T::ZERO; size.ggsw_len()],
            scratch: Glwe::zero(size.glwe_len()),
            external_product: NttGlweExternalProductWorkspace::new(size),
        }
    }
}

impl<T: FheUint> SparseGlweBlindRotationWorkspace<T> {
    /// Blind-rotates an encoded LUT into a coefficient-domain GLWE ciphertext.
    ///
    /// Uses ordinary PBS quantization (rotation step one). Quantizes each input
    /// coefficient once to `2N`, initializes a trivial
    /// accumulator with `X^(-R(b)) * LUT`, then applies one external product per
    /// bucket. Its control encrypts the selected `X^R(a[i])`, or `1` if no entry
    /// is selected. All buckets and encrypted zero entries are processed.
    /// The caller owns the output; this workspace is reused without online allocation.
    ///
    /// # Correctness
    ///
    /// The input must use this key's small-LWE secret. Input and LUT coefficients
    /// must be canonical under [`SparseGlweBootstrappingKey::input_modulus`]. The LUT has `N` encoded
    /// coefficients; the caller is responsible for its encoding and noise margin.
    /// This raw operation performs neither key switching nor sample extraction.
    ///
    /// # Panics
    ///
    /// Panics if input, LUT, output or workspace layouts, or the NTT length/modulus
    /// do not match this key. These checks precede output writes.
    pub fn blind_rotate_lookup_table_to<Table, A, B, C>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
        input: &Lwe<A>,
        lookup_table: &Polynomial<B>,
        output: &mut Glwe<C>,
        ntt: &Table,
    ) where
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: Data<Elem = T>,
        C: DataMut<Elem = T>,
    {
        let size = key.size();
        let poly_length = size.glwe_size().poly_length().get();
        let modulus = key.input_modulus();
        assert_eq!(
            (
                input.dimension(),
                lookup_table.as_ref().len(),
                output.as_ref().len()
            ),
            (key.input_dimension().get(), poly_length, size.glwe_len()),
            "sparse blind-rotation input, LUT or output layout mismatch"
        );
        assert_eq!(
            (self.input_exponents.len(), self.external_product.size()),
            (key.input_dimension().get(), size),
            "sparse blind-rotation workspace layout mismatch"
        );
        assert_eq!(
            ntt.poly_length().get(),
            poly_length,
            "sparse blind-rotation NTT length mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "sparse blind-rotation NTT modulus mismatch"
        );

        self.blind_rotate_interleaved_lookup_table_kernel_to(
            key,
            input.as_view(),
            lookup_table.as_view(),
            1,
            output.as_mut_view(),
            ntt,
        );
    }

    /// The public raw wrapper or evaluator has checked layouts, table and LUT.
    /// The rotation step is the compiled LUT's padded output count; every mask
    /// and body coefficient must use this same step to preserve output slots.
    pub(crate) fn blind_rotate_interleaved_lookup_table_kernel_to<Table>(
        &mut self,
        key: &SparseGlweBootstrappingKey<T, BarrettModulus<T>>,
        input: Lwe<&[T]>,
        lookup_table: Polynomial<&[T]>,
        rotation_step: usize,
        mut output: Glwe<&mut [T]>,
        ntt: &Table,
    ) where
        Table: NttTable<ValueT = T>,
    {
        let size = key.size();
        let poly_length = size.glwe_size().poly_length().get();
        let modulus = key.input_modulus();
        let SparseGlweBlindRotationWorkspace {
            input_exponents,
            aggregate,
            scratch,
            external_product,
        } = self;
        let modulus_switch = if rotation_step == 1 {
            key.rotation_modulus_switch()
        } else {
            RotationModulusSwitch::new(modulus, 2 * poly_length, rotation_step)
        };
        modulus_switch.exponent_slice_to(input.a(), input_exponents);
        let initial_exponent =
            modulus_switch.exponent(input.b()).wrapping_neg() & (2 * poly_length - 1);
        let (mask, body) = output.a_b_mut_slices(poly_length);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(initial_exponent, &mut Polynomial(body), modulus);

        // Bound the aggregation working set while keeping complete polynomials.
        // Small GGSWs fit in one tile; larger ones reuse each tile across entries.
        let tile_length = (16 * 1024 / size_of::<T>() / poly_length).max(1) * poly_length;
        let group_capacity = super::aggregation::max_group_len(modulus.value());
        let mut output_is_current = true;
        for bucket_index in 0..key.bucket_count() {
            let (indices, ciphertexts) = key.bucket_data(bucket_index);
            let (selections, dummy) = ciphertexts.split_at(indices.len() * size.ggsw_len());
            // Every bucket has a dummy, even if publicly empty. It overwrites the
            // previous bucket's NTT values before adding the rotated selections.
            aggregate.copy_from_slice(dummy);
            // Use at least two pairs and keep the whole bucket in one group.
            // Insufficient headroom retains the bounded pair kernel below.
            let use_groups = indices.len() >= 4 && indices.len() <= group_capacity;
            for (tile_index, tile) in aggregate.chunks_mut(tile_length).enumerate() {
                let start = tile_index * tile_length;
                let end = start + tile.len();
                // Pairing only improved the measured u64 NTT path. Retain the
                // single-input vector loop for the other word widths.
                if T::BITS != 64 {
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
                    continue;
                }
                let ggsw_len = size.ggsw_len();
                if use_groups {
                    super::aggregation::add_rotated_group_assign(
                        indices,
                        selections,
                        input_exponents,
                        tile,
                        start,
                        size,
                        modulus,
                    );
                    continue;
                }
                // Fuse two rotations and correct once per pair, retaining [0,2q)
                // residues until the complete bucket is normalized before NTT.
                let (index_pairs, index_tail) = indices.as_chunks::<2>();
                let mut selection_pairs = selections.chunks_exact(2 * ggsw_len);
                for (indices, pair) in index_pairs.iter().zip(selection_pairs.by_ref()) {
                    let (a, b) = pair.split_at(ggsw_len);
                    // A tile contains complete polynomials but need not be a
                    // complete GGSW, so use the shared coefficient-batch kernel.
                    primus_poly::lazy_add_mul_monomial_pair_assign(
                        tile,
                        &a[start..end],
                        input_exponents[indices[0]],
                        &b[start..end],
                        input_exponents[indices[1]],
                        poly_length,
                        modulus,
                    );
                }
                if let Some(&index) = index_tail.first() {
                    let selection = selection_pairs.remainder();
                    primus_poly::lazy_add_mul_monomial_assign(
                        tile,
                        &selection[start..end],
                        input_exponents[index],
                        poly_length,
                        modulus,
                    );
                }
            }
            if T::BITS == 64 && !use_groups {
                // The ordinary NTT entry requires canonical coefficients.
                modulus.reduce_once_slice_assign(aggregate);
            }
            let aggregate_ntt = Ggsw::new(aggregate.as_mut_slice()).into_ntt_form(ntt);
            if output_is_current {
                aggregate_ntt.external_product_to(
                    &output,
                    scratch,
                    key.basis(),
                    modulus,
                    ntt,
                    external_product,
                );
            } else {
                aggregate_ntt.external_product_to(
                    scratch,
                    &mut output,
                    key.basis(),
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
