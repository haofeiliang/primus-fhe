//! NTT packing key switching with one GLev per input LWE secret coefficient.

use primus_data::{Data, DataMut};
use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, glev::NttGlev, glwe::Glwe, lwe::Lwe};
use primus_lwe::LweSecretKeyRef;
use primus_ntt::NttTable;
use primus_poly::{NttPolynomial, Polynomial};
use primus_reduce::FieldContext;
use zeroize::Zeroizing;

use crate::{
    GlevParameters, NttGadgetEncryptContext, NttGlweKeySwitchingContext, NttGlweSecretKey,
};

/// NTT GLev encryptions of an independent input LWE secret's scalar coefficients.
///
/// Storage follows `[input coefficient][level][GLWE component][NTT coefficient]`.
/// Each GLev encrypts a constant polynomial under the output GLWE secret.
/// Input and output use the same ciphertext modulus and message encoding.
#[derive(Clone)]
pub struct NttLwePackingKeySwitchingKey<T: FheUint> {
    data: Vec<T>,
    input_dimension: usize,
    output_size: GadgetSize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> NttLwePackingKeySwitchingKey<T> {
    /// Generates a packing key from an arbitrary LWE secret to the output GLWE secret.
    ///
    /// # Correctness
    ///
    /// The input secret must satisfy [`LweSecretKeyRef`]'s coefficient-range
    /// contract under `params.cipher_modulus()`. The output secret must use the
    /// supplied NTT table's representation.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the input dimension is zero, storage length
    /// overflows, or the output key, NTT or workspace do not match `params`.
    pub fn generate<M, Table, R>(
        input_secret_key: LweSecretKeyRef<'_, T>,
        output_secret_key: &NttGlweSecretKey<T>,
        params: &GlevParameters<T, M>,
        ntt: &Table,
        rng: &mut R,
        context: &mut NttGadgetEncryptContext<T>,
    ) -> Self
    where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let input_dimension = input_secret_key.dimension();
        assert!(input_dimension != 0, "input LWE dimension must be nonzero");
        input_dimension
            .checked_add(1)
            .expect("input LWE length overflow");
        output_secret_key.assert_gadget_compatible(params, ntt);
        context.assert_glev_compatible(params.size());
        let length = input_dimension
            .checked_mul(params.glev_len())
            .expect("packing key length overflow");
        let mut data = vec![T::ZERO; length];
        let mut message = Zeroizing::new(vec![T::ZERO; params.poly_length()]);
        let mut entries = data.chunks_exact_mut(params.glev_len());
        super::for_each_secret(input_secret_key, params.cipher_modulus(), |secret| {
            message[0] = secret;
            output_secret_key.encrypt_glev_kernel_to(
                &Polynomial::new(message.as_slice()),
                &mut NttGlev::new(entries.next().expect("one GLev per secret coefficient")),
                params,
                ntt,
                rng,
                context,
            );
        });
        Self {
            data,
            input_dimension,
            output_size: params.size(),
            basis: params.basis().clone(),
        }
    }

    /// Returns the input LWE dimension.
    #[must_use]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the output GLWE layout and key decomposition level count.
    #[must_use]
    pub fn output_size(&self) -> GadgetSize {
        self.output_size
    }

    /// Returns the decomposition basis stored with this key.
    #[must_use]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the NTT key data in coefficient/level/component order.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Converts one LWE to a GLWE whose target message is constant.
    ///
    /// Inherits [`Self::pack_lwes_to`]'s correctness and workspace contracts.
    ///
    /// # Panics
    ///
    /// Inherits [`Self::pack_lwes_to`]'s checks and also rejects input that is
    /// not exactly one LWE of this key's input dimension, before output writes.
    pub fn key_switch_to<M, Table, A, B>(
        &self,
        input: &Lwe<A>,
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: Data<Elem = T>,
        B: DataMut<Elem = T>,
    {
        assert_eq!(
            input.as_ref().len(),
            self.input_dimension + 1,
            "packing input LWE dimension mismatch"
        );
        self.pack_lwes_to(input.as_ref(), output, modulus, ntt, context);
    }

    /// Packs `p` LWEs into a coefficient-domain GLWE targeting `sum_i m_i X^i`.
    ///
    /// Input is a flat slice of complete `[mask, body]` LWEs. Any `p` in
    /// `1..=N` is accepted. The target message tail `p..N` is zero; the noisy
    /// phase need not be zero there. All output coefficients are overwritten.
    /// Uses an output-layout GLWE key-switch context without allocating.
    ///
    /// # Correctness
    ///
    /// Inputs must use the secret from key generation and canonical residues
    /// under `modulus`. Use the key's NTT representation. No message rescaling
    /// is applied. The phase includes input noise, decomposition error weighted
    /// by the input secret, and accumulated key noise, including in the tail.
    /// Parameters must provide enough decoding margin for the batch size.
    ///
    /// # Panics
    ///
    /// Panics before writes if the batch is empty, incomplete or larger than N,
    /// or the output, modulus, NTT or workspace do not match this key.
    pub fn pack_lwes_to<M, Table, B>(
        &self,
        input: &[T],
        output: &mut Glwe<B>,
        modulus: M,
        ntt: &Table,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        B: DataMut<Elem = T>,
    {
        let size = self.output_size.glwe_size();
        let poly_length = size.poly_length();
        let count = super::check_batch(input.len(), self.input_dimension, poly_length);
        assert_eq!(
            output.as_ref().len(),
            size.glwe_len(),
            "packing output GLWE layout mismatch"
        );
        assert_eq!(
            Some(modulus.value()),
            self.basis.modulus(),
            "packing ciphertext modulus mismatch"
        );
        assert_eq!(
            ntt.modulus(),
            modulus.value(),
            "packing NTT modulus mismatch"
        );
        assert_eq!(
            ntt.poly_length(),
            poly_length,
            "packing NTT polynomial length mismatch"
        );
        assert_eq!(
            context.adjusted_poly.len(),
            poly_length,
            "packing workspace polynomial length mismatch"
        );
        assert_eq!(
            context.accumulator.as_ref().len(),
            size.glwe_len(),
            "packing workspace GLWE layout mismatch"
        );

        // For D[j,l](X) = sum_i digit_l(a[i,j]) X^i, compute
        // (0, sum_i b_i X^i) - sum_{j,l} D[j,l](X) * K[j,l].
        let lwe_len = self.input_dimension + 1;
        context.accumulator.set_zero();
        if count == 1 {
            // Frequent small digits avoid costly modular products. On Ryzen 9955HX3D,
            // large-key benchmarks (d=512..2048, N=1024..8192) support this cutoff
            // in default and SIMD builds; larger tested bases had no consistent gain.
            // Select once so the general kernel has no per-digit special cases.
            if self.basis.log_basis() <= 6 {
                self.accumulate_single::<true, _>(input, modulus, context);
            } else {
                self.accumulate_single::<false, _>(input, modulus, context);
            }
        } else {
            for (j, entry) in self
                .data
                .chunks_exact(self.output_size.glev_len())
                .enumerate()
            {
                for ((adjusted, carry), lwe) in context.adjusted_poly[..count]
                    .iter_mut()
                    .zip(&mut context.carries[..count])
                    .zip(input.chunks_exact(lwe_len))
                {
                    (*adjusted, *carry) = self.basis.init_value_carry(lwe[j]);
                }
                for (decomposer, key_glwe) in self
                    .basis
                    .decomposer_iter()
                    .zip(NttGlev::new(entry).iter_ntt_glwe(size.glwe_len()))
                {
                    decomposer.decompose_slice_to(
                        &context.adjusted_poly[..count],
                        &mut context.decomposed_ntt[..count],
                        &mut context.carries[..count],
                    );
                    // Transform overwrites the whole polynomial; reset the unused tail at every level.
                    context.decomposed_ntt[count..].fill(T::ZERO);
                    ntt.transform_slice(&mut context.decomposed_ntt);
                    context.accumulator.add_mul_ntt_polynomial_assign(
                        &key_glwe,
                        &NttPolynomial::new(context.decomposed_ntt.as_slice()),
                        modulus,
                    );
                }
            }
        }
        context.accumulator.write_coeff_form(output, ntt);
        output.neg_assign(modulus);
        let (_, body) = output.a_b_mut_slices(poly_length);
        for (output, lwe) in body[..count].iter_mut().zip(input.chunks_exact(lwe_len)) {
            modulus.reduce_add_assign(output, lwe[self.input_dimension]);
        }
    }

    /// Accumulates one validated LWE mask using scalar digits, without digit transforms.
    fn accumulate_single<const SMALL_DIGITS: bool, M: FieldContext<T>>(
        &self,
        input: &[T],
        modulus: M,
        context: &mut NttGlweKeySwitchingContext<T>,
    ) {
        let glwe_len = self.output_size.glwe_len();
        let minus_one = modulus.reduce_neg(T::ONE);
        let minus_two = modulus.reduce_neg(T::TWO);
        for (&coefficient, entry) in input[..self.input_dimension]
            .iter()
            .zip(self.data.chunks_exact(self.output_size.glev_len()))
        {
            let (adjusted, mut carry) = self.basis.init_value_carry(coefficient);
            for (decomposer, key_glwe) in self
                .basis
                .decomposer_iter()
                .zip(entry.chunks_exact(glwe_len))
            {
                let (digit, next_carry) = decomposer.decompose(adjusted, carry);
                carry = next_carry;
                let acc = context.accumulator.as_mut();
                // Branch once per GLWE block, leaving the slice kernels vectorizable.
                // For ±2 the measured savings outweigh the extra add/sub pass;
                // zero also avoids reading the key block entirely.
                if SMALL_DIGITS {
                    if digit.is_zero() {
                        continue;
                    } else if digit == T::ONE {
                        modulus.reduce_add_slice_assign(acc, key_glwe);
                        continue;
                    } else if digit == minus_one {
                        modulus.reduce_sub_slice_assign(acc, key_glwe);
                        continue;
                    } else if digit == T::TWO {
                        modulus.reduce_add_slice_assign(acc, key_glwe);
                        modulus.reduce_add_slice_assign(acc, key_glwe);
                        continue;
                    } else if digit == minus_two {
                        modulus.reduce_sub_slice_assign(acc, key_glwe);
                        modulus.reduce_sub_slice_assign(acc, key_glwe);
                        continue;
                    }
                }
                modulus.reduce_add_mul_scalar_slice_assign(acc, key_glwe, digit);
            }
        }
    }
}
