//! Reference sparse blind rotation: coefficient aggregation, NTT, external product.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::{
    context::NttGlweExternalProductContext,
    ggsw::{Ggsw, NttGgsw},
    glwe::Glwe,
    lwe::Lwe,
};
use primus_ntt::NttTable;
use primus_poly::Polynomial;

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

        let SparseGlweBlindRotationContext {
            input_exponents,
            aggregate,
            aggregate_ntt,
            scratch,
            external_product,
        } = context;
        let quantizer = self.input_quantizer();
        quantizer.exponent_slice_to(input.a(), input_exponents);
        let initial_exponent = quantizer.exponent(input.b()).wrapping_neg() & (2 * poly_length - 1);
        let (mask, body) = output.a_b_mut_slices(poly_length);
        mask.fill(T::ZERO);
        lookup_table.mul_monomial_to(initial_exponent, &mut Polynomial(body), modulus);

        let mut output_is_current = true;
        for bucket_index in 0..self.bucket_count() {
            let (indices, mut selections) = self.bucket(bucket_index);
            aggregate.set_zero();
            for (&input_index, selection) in indices.iter().zip(&mut selections) {
                aggregate.add_mul_monomial_assign(
                    &selection,
                    input_exponents[input_index],
                    poly_length,
                    modulus,
                );
            }
            // The final entry is always the dummy, including publicly empty buckets.
            let dummy = selections
                .next()
                .expect("sparse bucket must contain a dummy");
            aggregate.add_assign(&dummy, modulus);
            aggregate.write_ntt_form(aggregate_ntt, ntt);
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
/// Stores input exponents, coefficient and NTT aggregates, a GLWE buffer and
/// external-product scratch. It contains no secret support or matching data.
pub struct SparseGlweBlindRotationContext<T: FheUint> {
    input_exponents: Vec<usize>,
    aggregate: Ggsw<Vec<T>>,
    aggregate_ntt: NttGgsw<Vec<T>>,
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
            aggregate: Ggsw::zero(size.ggsw_len()),
            aggregate_ntt: NttGgsw::zero(size.ggsw_len()),
            scratch: Glwe::zero(size.glwe_len()),
            external_product: NttGlweExternalProductContext::new(size),
        }
    }
}
