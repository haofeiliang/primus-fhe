//! Square-matrix LWE public-key encryption.

mod batch;

use primus_data::DataMut;
use primus_distr::{DiscreteGaussian, sample_sparse_ternary_values_to};
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;

use crate::{LweCiphertext, LweParameters, LweSecretKeyRef, PlaintextEmbedding};

// A full row block consumes whole random words for any ciphertext tile count.
const ROWS_PER_BLOCK: usize = 16;

/// A Lindner–Peikert-style public key `(A, b = A s + e)` with square `A`.
///
/// Stores `n` contiguous rows `[A_i, b_i]`, each an LWE encryption of zero
/// under the same `n`-dimensional secret. Encryption samples independent
/// ephemeral coefficients with `Pr[r_i = 0] = 1/2` and
/// `Pr[r_i = -1] = Pr[r_i = 1] = 1/4`, and fresh Gaussian errors `e1, e2`:
///
/// ```text
/// a = A^T r + e1
/// c = b^T r + e2 + Encode(message)
/// ```
///
/// The ciphertext `[a, c]` uses the existing LWE layout and secret-key decoder.
/// This is a CPA encryption primitive, not a KEM or a CCA transform.
/// The square-matrix construction follows
/// [Lindner and Peikert](https://eprint.iacr.org/2010/613), with the ephemeral
/// distribution fixed to the sparse ternary law above.
/// Encryption packs sixteen ephemeral coefficients per random word. Unused
/// bits are discarded after each ciphertext or batch tile; seeded ciphertext
/// bytes are not guaranteed to remain identical across library versions.
///
/// # Correctness
///
/// Decryption requires `e^T r + e2 - e1^T s` to stay within the plaintext
/// codec's decoding margin. Small centered secret coefficients are needed to
/// control `e1^T s`. The high-level methods use `params.noise_distribution()`
/// for both `e1` and `e2`; generation uses its own supplied parameters for `e`.
/// None of these samplers specifies the *total* output noise distribution.
///
/// Parameters must jointly ensure LWE security for the long-term secret and
/// the ephemeral sparse ternary secret, and the desired decryption failure
/// probability. This type validates dimensions and modulus identity, not these
/// security or noise bounds. Existing secret-key parameters are not necessarily
/// suitable public-key parameters.
#[derive(Clone)]
pub struct LwePublicKey<T: FheUint> {
    data: Vec<T>,
    dimension: usize,
    modulus_minus_one: T,
}

impl<T: FheUint> LwePublicKey<T> {
    /// Generates `n` independent zero encryptions under `secret_key`.
    ///
    /// Borrows encoded or signed coefficients without copying the secret.
    /// Only the dimension and modulus identity are retained from
    /// `params`; the plaintext codec and samplers remain caller-owned.
    ///
    /// # Correctness
    ///
    /// The secret must satisfy [`LweSecretKeyRef`]'s coefficient-range contract
    /// under `params`' modulus.
    /// The [type's security and noise requirements](Self#correctness) apply.
    ///
    /// # Panics
    ///
    /// Panics before sampling if the secret dimension differs from the nonzero
    /// parameter dimension or the public-key storage length overflows `usize`.
    #[must_use]
    pub fn generate<M, R>(
        secret_key: LweSecretKeyRef<'_, T>,
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> Self
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let dimension = params.dimension();
        assert_eq!(
            secret_key.dimension(),
            dimension,
            "LWE public-key dimension mismatch"
        );
        let row_len = dimension + 1;
        let length = dimension
            .checked_mul(row_len)
            .expect("LWE public-key storage length overflow");
        let mut data = vec![T::ZERO; length];
        let modulus = params.cipher_modulus();
        let uniform = params.cipher_modulus_uniform_distr();
        let noise = params.noise_distribution();
        for row in data.chunks_exact_mut(row_len) {
            secret_key.encrypt_encoded_to(
                T::ZERO,
                &mut Lwe::new(row),
                modulus,
                uniform,
                noise,
                rng,
            );
        }
        Self {
            data,
            dimension,
            modulus_minus_one: modulus.minus_one(),
        }
    }

    /// Returns the dimension of the secret and output LWE ciphertexts.
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns `q - 1`, including `T::MAX` for the native modulus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.modulus_minus_one
    }

    /// Returns `n` row-major `[A_i, b_i]` blocks of `n + 1` canonical residues.
    #[must_use]
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Encrypts a canonical encoded residue in a newly allocated ciphertext.
    ///
    /// Zero produces a randomized encryption of zero. The correctness and
    /// panic conditions of [`Self::encrypt_encoded_to`] apply, except that the
    /// output length is supplied by this key.
    #[must_use]
    pub fn encrypt_encoded<M, R>(
        &self,
        plaintext: T,
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(modulus);
        let mut output = LweCiphertext::zero(self.dimension);
        self.encrypt_encoded_slice(plaintext, output.as_mut(), modulus, noise, rng);
        output
    }

    /// Overwrites `output` with an encryption of an already encoded residue.
    ///
    /// Samples fresh `e1, e2` from `noise`, then streams ephemeral coefficients
    /// while accumulating public-key rows. No allocation or scratch is needed.
    /// Encryption branches on ephemeral coefficients and skips zero rows;
    /// this is not a constant-time implementation.
    ///
    /// # Correctness
    ///
    /// `plaintext` must be in `[0,q)`, and `noise` must encode its samples under
    /// `modulus`. These conditions are not checked. The
    /// [type's security and noise requirements](Self#correctness) also apply.
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling if the modulus differs from the key's
    /// or `output` does not have exactly `self.dimension() + 1` coefficients.
    /// A panicking RNG can leave partially written output.
    pub fn encrypt_encoded_to<M, R>(
        &self,
        plaintext: T,
        output: &mut Lwe<impl DataMut<Elem = T>>,
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(modulus);
        let output = output.as_mut();
        assert_eq!(
            output.len(),
            self.dimension + 1,
            "LWE public-key output length mismatch"
        );
        self.encrypt_encoded_slice(plaintext, output, modulus, noise, rng);
    }

    /// Encrypts a canonical message in `[0,t)` with unsigned embedding.
    ///
    /// See [`Self::encrypt_with_embedding`] for correctness and panic conditions.
    #[must_use]
    #[inline]
    pub fn encrypt<R, M>(
        &self,
        message: T,
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.encrypt_with_embedding(message, params, rng, PlaintextEmbedding::Unsigned)
    }

    /// Overwrites existing storage using unsigned message embedding.
    ///
    /// See [`Self::encrypt_with_embedding_to`] for correctness and panic conditions.
    #[inline]
    pub fn encrypt_to<R, M>(
        &self,
        message: T,
        output: &mut Lwe<impl DataMut<Elem = T>>,
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.encrypt_with_embedding_to(message, output, params, rng, PlaintextEmbedding::Unsigned);
    }

    /// Encodes a canonical message, then encrypts the encoded residue.
    ///
    /// Both embeddings accept unsigned residues in `[0,t)`; under centered
    /// embedding, `t - 1` represents `-1`.
    ///
    /// # Correctness
    ///
    /// The [type's security and noise requirements](Self#correctness) apply.
    /// The plaintext codec must match the decoder's encoding parameters.
    ///
    /// # Panics
    ///
    /// Panics before allocating or sampling if the parameter dimension or
    /// modulus differs from the key's, or the message violates
    /// [`RoundedCodec::encode_value`](primus_encoding::RoundedCodec::encode_value).
    #[must_use]
    pub fn encrypt_with_embedding<R, M>(
        &self,
        message: T,
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        assert_eq!(
            params.dimension(),
            self.dimension,
            "LWE public-key parameter dimension mismatch"
        );
        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.encrypt_encoded(
            plaintext,
            params.cipher_modulus(),
            params.noise_distribution(),
            rng,
        )
    }

    /// Encodes a message and overwrites all output coefficients without allocating.
    ///
    /// # Correctness
    ///
    /// The correctness conditions of [`Self::encrypt_with_embedding`] apply.
    ///
    /// # Panics
    ///
    /// Panics before writing or sampling under the conditions of
    /// [`Self::encrypt_with_embedding`], or if the output length is not
    /// `self.dimension() + 1`. A panicking RNG can leave partial output.
    pub fn encrypt_with_embedding_to<R, M>(
        &self,
        message: T,
        output: &mut Lwe<impl DataMut<Elem = T>>,
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        assert_eq!(
            params.dimension(),
            self.dimension,
            "LWE public-key parameter dimension mismatch"
        );
        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.encrypt_encoded_to(
            plaintext,
            output,
            params.cipher_modulus(),
            params.noise_distribution(),
            rng,
        );
    }

    #[inline]
    fn check_modulus<M: RingContext<T>>(&self, modulus: M) {
        assert_eq!(
            modulus.minus_one(),
            self.modulus_minus_one,
            "LWE public-key modulus mismatch"
        );
    }

    /// Overwrites a validated `n + 1` output slice under the key's modulus.
    /// Interleaved bodies let one slice kernel accumulate both `A^T r` and
    /// `b^T r`, without a transpose, temporary secret vector, or extra pass.
    /// Ternary coefficients select addition, subtraction, or no work once per
    /// row, outside the slice kernel's coefficient loop. Gaussian errors are
    /// sampled first, then packed ternary coefficients in matrix-row order.
    fn encrypt_encoded_slice<M, R>(
        &self,
        plaintext: T,
        output: &mut [T],
        modulus: M,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        noise.sample_to(output, rng);
        modulus.reduce_add_assign(&mut output[self.dimension], plaintext);
        let row_len = self.dimension + 1;
        // Clamping keeps the block length within the validated key allocation.
        let block_len = self.dimension.min(ROWS_PER_BLOCK) * row_len;
        let mut ephemeral = [0i8; ROWS_PER_BLOCK];
        for rows in self.data.chunks(block_len) {
            let coefficients = &mut ephemeral[..rows.len() / row_len];
            sample_sparse_ternary_values_to(coefficients, -1, rng);
            for (row, &coefficient) in rows.chunks_exact(row_len).zip(coefficients.iter()) {
                match coefficient {
                    1 => modulus.reduce_add_slice_assign(output, row),
                    -1 => modulus.reduce_sub_slice_assign(output, row),
                    _ => {}
                }
            }
        }
    }
}
