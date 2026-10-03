use super::LweSecretKey;
use crate::batch::{batch_iter, batch_len, check_batch};
use crate::{LweParameters, PlaintextEmbedding};
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_lattice::lwe::{LweIter, LweIterMut};
use primus_reduce::RingContext;
use rand::distr::Uniform;

impl<T: FheUint> LweSecretKey<T> {
    /// Encrypts independent messages with unsigned embedding in one allocation.
    /// See [`Self::encrypt_batch_with_embedding_to`] for contracts.
    #[must_use]
    pub fn encrypt_batch<M, R>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_batch_with_embedding(messages, params, rng, PlaintextEmbedding::Unsigned)
    }

    /// Encrypts independent messages with unsigned embedding into existing storage.
    /// See [`Self::encrypt_batch_with_embedding_to`] for contracts.
    pub fn encrypt_batch_to<M, R>(
        &self,
        messages: &[T],
        output: &mut [T],
        params: &LweParameters<T, M>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.encrypt_batch_with_embedding_to(
            messages,
            output,
            params,
            rng,
            PlaintextEmbedding::Unsigned,
        );
    }

    /// Allocates a contiguous batch using unsigned or centered embedding.
    ///
    /// See [`Self::encrypt_batch_with_embedding_to`] for contracts. Also panics
    /// if the total storage length overflows.
    #[must_use]
    pub fn encrypt_batch_with_embedding<M, R>(
        &self,
        messages: &[T],
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = vec![T::ZERO; batch_len(self.dimension(), messages.len())];
        self.encrypt_batch_with_embedding_to(messages, &mut output, params, rng, embedding);
        output
    }

    /// Encodes and encrypts each message directly into its ciphertext.
    ///
    /// No allocation or scratch is needed. Empty batches consume no randomness.
    /// RNG ordering is not guaranteed to match repeated single-message calls.
    /// Both embeddings accept canonical residues in `[0,t)`.
    /// Output contains `messages.len()` consecutive `[mask, body]` chunks of
    /// length `self.dimension() + 1`; empty output is valid for empty messages.
    ///
    /// # Correctness
    ///
    /// The key, modulus and noise must satisfy [`Self::encrypt_with_embedding_to`].
    /// The batch count is unrestricted by the LWE dimension.
    ///
    /// # Panics
    ///
    /// Parameter dimension/modulus or output length mismatches, and length overflow,
    /// panic before writing or sampling.
    /// Message range or RNG failures may leave partial output
    /// and may have consumed randomness for earlier messages.
    pub fn encrypt_batch_with_embedding_to<M, R>(
        &self,
        messages: &[T],
        output: &mut [T],
        params: &LweParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(params.cipher_modulus());
        assert_eq!(
            params.dimension().get(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        let lwe_len = check_batch(output, self.dimension(), messages.len());

        // Validate the owning domain once; each entry uses the same raw key view.
        let key = self.as_view();
        for (mut ciphertext, &message) in LweIterMut::new(output, lwe_len).zip(messages) {
            let plaintext = params.plaintext_codec().encode_value(message, embedding);
            key.encrypt_encoded_to(
                plaintext,
                &mut ciphertext,
                params.cipher_modulus(),
                params.cipher_modulus_uniform_distr(),
                params.noise_distribution(),
                rng,
            );
        }
    }

    /// Encrypts canonical encoded residues into one newly allocated batch.
    /// See [`Self::encrypt_encoded_batch_to`] for contracts. Also panics if
    /// the total storage length overflows.
    #[must_use]
    pub fn encrypt_encoded_batch<M, R>(
        &self,
        plaintexts: &[T],
        modulus: M,
        uniform: Uniform<T>,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) -> Vec<T>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        let mut output = vec![T::ZERO; batch_len(self.dimension(), plaintexts.len())];
        self.encrypt_encoded_batch_to(plaintexts, &mut output, modulus, uniform, noise, rng);
        output
    }

    /// Encrypts canonical encoded residues into existing batch storage.
    ///
    /// No allocation or scratch is needed. Empty batches consume no randomness.
    /// RNG ordering need not match repeated single-message encryption.
    /// Output must contain exactly `plaintexts.len() * (self.dimension() + 1)`
    /// coefficients, with one `[mask, body]` chunk per plaintext.
    ///
    /// # Correctness
    ///
    /// Every plaintext and key coefficient must be canonical under `modulus`.
    /// Samplers must satisfy [`super::LweSecretKeyRef::encrypt_encoded_to`].
    ///
    /// # Panics
    ///
    /// Modulus or output length mismatches, or length overflow, panic before writing
    /// or sampling.
    /// A panicking RNG can leave partial output.
    pub fn encrypt_encoded_batch_to<M, R>(
        &self,
        plaintexts: &[T],
        output: &mut [T],
        modulus: M,
        uniform: Uniform<T>,
        noise: &DiscreteGaussian<T>,
        rng: &mut R,
    ) where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_modulus(modulus);
        let lwe_len = check_batch(output, self.dimension(), plaintexts.len());

        let key = self.as_view();
        for (&plaintext, mut ciphertext) in plaintexts.iter().zip(LweIterMut::new(output, lwe_len))
        {
            key.encrypt_encoded_to(plaintext, &mut ciphertext, modulus, uniform, noise, rng);
        }
    }

    /// Allocates canonical phases `b - <a,s>` in ciphertext order.
    /// The correctness conditions of [`Self::decrypt_phase_batch_to`] apply.
    ///
    /// # Panics
    ///
    /// Panics if the recorded key modulus differs from `modulus`, or the input
    /// length is not a multiple of `self.dimension() + 1`.
    /// Empty input returns an empty vector.
    #[must_use]
    pub fn decrypt_phase_batch<M: RingContext<T>>(&self, input: &[T], modulus: M) -> Vec<T> {
        self.check_modulus(modulus);
        let key = self.as_ref();
        batch_iter(input, key.len())
            .map(|ciphertext| {
                modulus.reduce_sub(
                    ciphertext.b(),
                    modulus.reduce_dot_product(ciphertext.a(), key),
                )
            })
            .collect()
    }

    /// Writes canonical phases into an exactly sized output slice without allocating.
    ///
    /// # Correctness
    ///
    /// Every ciphertext and key coefficient must be canonical under `modulus`,
    /// satisfying [`primus_reduce::ReduceDotProduct`].
    ///
    /// # Panics
    ///
    /// Panics before writing if the recorded key modulus differs from `modulus`,
    /// if `input.len() != output.len() * (self.dimension() + 1)`, or if that length
    /// overflows.
    pub fn decrypt_phase_batch_to<M: RingContext<T>>(
        &self,
        input: &[T],
        output: &mut [T],
        modulus: M,
    ) {
        self.check_modulus(modulus);
        let lwe_len = check_batch(input, self.dimension(), output.len());
        let key = self.as_ref();
        for (ciphertext, phase) in LweIter::new(input, lwe_len).zip(output) {
            *phase = modulus.reduce_sub(
                ciphertext.b(),
                modulus.reduce_dot_product(ciphertext.a(), key),
            );
        }
    }

    /// Decrypts consecutive `[mask, body]` chunks into one allocated message vector.
    /// The correctness conditions of [`Self::decrypt_batch_to`] apply.
    ///
    /// # Panics
    ///
    /// Panics if the parameter dimension or modulus differs from the key or
    /// input contains an incomplete ciphertext. Empty input returns an empty vector.
    #[must_use]
    pub fn decrypt_batch<M>(&self, input: &[T], params: &LweParameters<T, M>) -> Vec<T>
    where
        M: RingContext<T>,
    {
        self.check_modulus(params.cipher_modulus());
        assert_eq!(
            params.dimension().get(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        let key = self.as_ref();
        let modulus = params.cipher_modulus();
        let codec = params.plaintext_codec();
        batch_iter(input, self.dimension())
            .map(|ciphertext| {
                let phase = modulus.reduce_sub(
                    ciphertext.b(),
                    modulus.reduce_dot_product(ciphertext.a(), key),
                );
                codec.decode_value(phase)
            })
            .collect()
    }

    /// Decrypts into an exactly sized message slice without allocating.
    /// Both encryption embeddings decode to canonical residues in `[0,t)`.
    /// Input contains `output.len()` chunks of `self.dimension() + 1` coefficients.
    ///
    /// # Correctness
    ///
    /// Every input ciphertext, the key and parameters must satisfy [`Self::decrypt`].
    ///
    /// # Panics
    ///
    /// Parameter dimension/modulus or input/output length mismatches, and length overflow,
    /// panic before writing.
    pub fn decrypt_batch_to<M>(&self, input: &[T], output: &mut [T], params: &LweParameters<T, M>)
    where
        M: RingContext<T>,
    {
        self.check_modulus(params.cipher_modulus());
        assert_eq!(
            params.dimension().get(),
            self.dimension(),
            "LWE batch parameter dimension mismatch"
        );
        let lwe_len = check_batch(input, self.dimension(), output.len());
        let key = self.as_ref();
        let modulus = params.cipher_modulus();
        let codec = params.plaintext_codec();
        for (ciphertext, message) in LweIter::new(input, lwe_len).zip(output) {
            let phase = modulus.reduce_sub(
                ciphertext.b(),
                modulus.reduce_dot_product(ciphertext.a(), key),
            );
            *message = codec.decode_value(phase);
        }
    }
}
