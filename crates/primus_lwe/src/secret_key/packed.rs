use primus_data::Data;
use primus_integer::FheUint;
use primus_lattice::lwe::MultiMsgLwe;
use primus_reduce::RingContext;
use rand::distr::Distribution;

use crate::{LweParameters, MultiMsgLweCiphertext, PlaintextEmbedding};

use super::LweSecretKey;

impl<T: FheUint> LweSecretKey<T> {
    /// Encrypts at most `params.dimension()` messages with unsigned embedding.
    ///
    /// See [`Self::encrypt_multi_messages_with_embedding`] for the layout,
    /// correctness and panic conditions.
    #[inline]
    pub fn encrypt_multi_messages<R, M>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> MultiMsgLweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        self.encrypt_multi_messages_with_embedding(
            messages,
            params,
            rng,
            PlaintextEmbedding::Unsigned,
        )
    }

    /// Encrypts multiple messages using the selected plaintext embedding.
    ///
    /// Stores a length-`n` mask followed by `messages.len()` bodies, where
    /// `n = params.dimension()`. Body `i` uses the mask rotated right by `i`
    /// with the first `i` coefficients negated. An empty message slice is allowed.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// Both embeddings accept canonical messages in `[0,t)`.
    ///
    /// # Panics
    ///
    /// Panics if the message count exceeds `n`, the storage length overflows,
    /// or a message lies outside `[0,t)`.
    #[inline]
    pub fn encrypt_multi_messages_with_embedding<R, M>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> MultiMsgLweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        debug_assert_eq!(self.dimension(), params.dimension());
        let mut output = allocate_packed(params.dimension(), messages.len());
        let (_, bodies) = output.a_b_mut(params.dimension());
        // Bodies start at zero: encode directly into the final storage before sampling.
        params
            .plaintext_codec()
            .add_encode_slice_assign(bodies, messages, embedding);
        self.encrypt_packed_bodies_assign(&mut output, params, rng);
        output
    }

    /// Encrypts multiple zeros using the secret key.
    ///
    /// Uses the layout and key contract of
    /// [`Self::encrypt_multi_messages_with_embedding`]. A zero count is allowed.
    ///
    /// # Panics
    ///
    /// Panics if `zero_count` exceeds `params.dimension()` or the storage length
    /// overflows.
    #[inline]
    pub fn encrypt_multi_zeros<R, Modulus>(
        &self,
        zero_count: usize,
        params: &LweParameters<T, Modulus>,
        rng: &mut R,
    ) -> MultiMsgLweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
        Modulus: RingContext<T>,
    {
        debug_assert_eq!(self.dimension(), params.dimension());
        let mut output = allocate_packed(params.dimension(), zero_count);
        self.encrypt_packed_bodies_assign(&mut output, params, rng);
        output
    }

    /// Samples the shared mask and adds each rotated mask product and noise to
    /// the encoded bodies. The caller supplies exactly `n + count` coefficients,
    /// with `count <= n`, canonical bodies, and a key matching the parameters.
    #[inline]
    fn encrypt_packed_bodies_assign<R, M>(
        &self,
        output: &mut MultiMsgLweCiphertext<T>,
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) where
        R: rand::Rng + rand::CryptoRng,
        M: RingContext<T>,
    {
        let dimension = params.dimension();
        let modulus = params.cipher_modulus();
        let (mask, bodies) = output.a_b_mut(dimension);
        mask.iter_mut()
            .zip(params.cipher_modulus_uniform_distr().sample_iter(&mut *rng))
            .for_each(|(out, sample)| *out = sample);
        for (index, body) in bodies.iter_mut().enumerate() {
            let product = self.multi_message_a_mul_s(mask, index, dimension, modulus);
            modulus.reduce_add_assign(body, product);
        }
        // Keep RNG state out of the rotated dot-product loop.
        for (body, error) in bodies
            .iter_mut()
            .zip(params.noise_distribution().sample_iter(rng))
        {
            modulus.reduce_add_assign(body, error);
        }
    }

    /// Decrypts the [`MultiMsgLweCiphertext<T>`] back to message.
    ///
    /// Returns canonical residues in `[0,t)` for either embedding, including an
    /// empty vector when the ciphertext retains no bodies.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// The ciphertext must use the mask/body layout of
    /// [`Self::encrypt_multi_messages_with_embedding`] and canonical coefficients
    /// under the same modulus. Original messages are recovered only within the
    /// codec's decoding margin.
    ///
    /// # Panics
    ///
    /// Panics if storage is shorter than `params.dimension()`, the body count
    /// exceeds that dimension, or a nonempty ciphertext has a mask/key length mismatch.
    #[inline]
    pub fn decrypt_multi_messages<M>(
        &self,
        cipher_text: &MultiMsgLwe<impl Data<Elem = T>>,
        params: &LweParameters<T, M>,
    ) -> Vec<T>
    where
        M: RingContext<T>,
    {
        let modulus = params.cipher_modulus();
        let dimension = params.dimension();

        debug_assert_eq!(self.dimension(), dimension);

        let (a, b) = cipher_text.a_b(dimension);

        debug_assert_eq!(a.len(), dimension);
        assert!(
            b.len() <= dimension,
            "packed LWE message count must not exceed the LWE dimension"
        );

        let mut messages: Vec<T> = b
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                let a_mul_s = self.multi_message_a_mul_s(a, i, dimension, modulus);
                modulus.reduce_sub(b, a_mul_s)
            })
            .collect();
        params.plaintext_codec().decode_slice_assign(&mut messages);

        messages
    }

    /// Computes the phase mask product for body `index`; `index < dimension`
    /// and both the mask and key have exactly `dimension` canonical coefficients.
    /// Negating the wrapped prefix implements the negacyclic extraction layout.
    #[inline]
    fn multi_message_a_mul_s<M>(&self, a: &[T], index: usize, dimension: usize, modulus: M) -> T
    where
        M: RingContext<T>,
    {
        if index == 0 {
            modulus.reduce_dot_product(a, self.as_ref())
        } else {
            let (mask_prefix, mask_suffix) = a.split_at(dimension - index);
            let (key_prefix, key_suffix) = self.as_ref().split_at(index);
            // <(-suffix, prefix), s> = <prefix, s[index..]> - <suffix, s[..index]>.
            // Two contiguous dot products retain the backend's slice/SIMD kernels.
            modulus.reduce_sub(
                modulus.reduce_dot_product(mask_prefix, key_suffix),
                modulus.reduce_dot_product(mask_suffix, key_prefix),
            )
        }
    }
}

/// Allocates the packed mask/body layout, enforcing its independent-mask limit.
#[inline]
fn allocate_packed<T: FheUint>(dimension: usize, count: usize) -> MultiMsgLweCiphertext<T> {
    // Beyond n bodies the negacyclic mask repeats up to sign, exposing message
    // sums or differences. Reject this before allocating or sampling output.
    assert!(
        count <= dimension,
        "packed LWE message count must not exceed the LWE dimension"
    );
    let length = dimension
        .checked_add(count)
        .expect("packed LWE storage length overflow");
    MultiMsgLweCiphertext::new(vec![T::ZERO; length])
}
