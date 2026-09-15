use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_reduce::RingContext;

use crate::{LweCiphertext, LweParameters, PlaintextEmbedding};

use super::LweSecretKey;

impl<T: FheUint> LweSecretKey<T> {
    /// Encrypts a canonical message in `[0,t)` with unsigned embedding.
    ///
    /// See [`Self::encrypt_with_embedding`] for correctness and panic conditions.
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

    /// Encodes the message with the selected embedding, then encrypts the encoded residue.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// Both embeddings accept residues in `[0,t)`; see
    /// [`RoundedCodec::encode_value`](primus_encoding::RoundedCodec::encode_value).
    ///
    /// # Panics
    ///
    /// Panics before allocating or sampling if `message` lies outside `[0,t)`.
    #[inline]
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
        debug_assert_eq!(self.dimension(), params.dimension());

        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.as_view().encrypt_encoded(
            plaintext,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        )
    }

    /// Encrypts a canonical message in `[0,t)` into existing storage.
    ///
    /// See [`Self::encrypt_with_embedding_to`] for contracts and panic conditions.
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

    /// Encodes a canonical message and overwrites all coefficients of `output`.
    /// No allocation is performed.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    ///
    /// # Panics
    ///
    /// Panics before writing if `message` is outside `[0,t)` or the output length
    /// is not `self.dimension() + 1`. A panicking RNG can leave partial output.
    #[inline]
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
        debug_assert_eq!(self.dimension(), params.dimension());
        let plaintext = params.plaintext_codec().encode_value(message, embedding);
        self.as_view().encrypt_encoded_to(
            plaintext,
            output,
            params.cipher_modulus(),
            params.cipher_modulus_uniform_distr(),
            params.noise_distribution(),
            rng,
        );
    }

    /// Decrypts the [`LweCiphertext<T>`] back to message.
    ///
    /// Returns a canonical residue in `[0,t)` for either encryption embedding.
    ///
    /// # Correctness
    ///
    /// The key must satisfy the [type's parameter contract](Self#correctness).
    /// The ciphertext must have dimension `params.dimension()` and canonical
    /// coefficients under the same modulus. Recovering the original message
    /// also requires its noise to remain within the codec's decoding margin.
    ///
    /// # Panics
    ///
    /// Panics if the ciphertext has no body or its mask length differs from the key length.
    #[inline]
    pub fn decrypt<M>(
        &self,
        cipher_text: &Lwe<impl Data<Elem = T>>,
        params: &LweParameters<T, M>,
    ) -> T
    where
        M: RingContext<T>,
    {
        let modulus = params.cipher_modulus();

        debug_assert_eq!(self.dimension(), params.dimension());
        let plaintext = self.as_view().decrypt_phase(cipher_text, modulus);

        params.plaintext_codec().decode_value(plaintext)
    }

    /// Decrypts the [`LweCiphertext<T>`] and computes noise under the selected embedding.
    ///
    /// Returns `(message, distance)`, where `message` is in `[0,t)` and `distance`
    /// is the nonnegative circular distance between the phase `b - <a,s>` and
    /// the re-encoding of that decoded message. It is not signed noise and does
    /// not detect a failure to recover the original message.
    ///
    /// The correctness and panic conditions of [`Self::decrypt`] apply.
    #[inline]
    pub fn decrypt_with_noise<M>(
        &self,
        cipher_text: &Lwe<impl Data<Elem = T>>,
        params: &LweParameters<T, M>,
        embedding: PlaintextEmbedding,
    ) -> (T, T)
    where
        M: RingContext<T>,
    {
        let modulus = params.cipher_modulus();

        debug_assert_eq!(self.dimension(), params.dimension());
        let plaintext = self.as_view().decrypt_phase(cipher_text, modulus);

        let message: T = params.plaintext_codec().decode_value(plaintext);
        let fresh: T = params.plaintext_codec().encode_value(message, embedding);

        (
            message,
            modulus
                .reduce_sub(plaintext, fresh)
                .min(modulus.reduce_sub(fresh, plaintext)),
        )
    }
}
