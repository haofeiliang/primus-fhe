mod boolean;
mod encryption_key;
mod error;
mod parameters;

pub use boolean::{BooleanDecryptor, BooleanEncryptor};
pub use encryption_key::EncryptionKey;
pub use error::{BooleanError, ClientError};
pub use parameters::LweClientParameters;

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_lattice::lwe::Lwe;
use primus_lwe::{LweCiphertext, LweSecretKeyRef};
use primus_reduce::RingContext;

/// Encrypts rounded TFHE messages into external LWE ciphertexts.
///
/// Both secret and public keys use the same message checks, encoding and output
/// reuse. Public keys inherit [`EncryptionKey`]'s identity and noise contracts.
/// Allocating methods return [`LweCiphertext`]; `*_to` methods take mutable LWE
/// views, obtained with `as_mut_view()` or by wrapping a borrowed slice in [`Lwe`].
pub struct Encryptor<'a, T: FheUint, M: RingContext<T>, Key = LweSecretKeyRef<'a, T>> {
    parameters: LweClientParameters<'a, T, M>,
    key: Key,
}

impl<'a, T: FheUint, M: RingContext<T>, Key: EncryptionKey<T, M>> Encryptor<'a, T, M, Key> {
    /// Checks the LWE key dimension and, for public keys, the ciphertext modulus.
    ///
    /// # Correctness
    ///
    /// The sampler and secret-range contracts of [`LweClientParameters`] apply.
    /// Public-key identity and combined noise follow [`EncryptionKey`].
    pub fn try_new(
        parameters: LweClientParameters<'a, T, M>,
        key: Key,
    ) -> Result<Self, ClientError> {
        key.check_compatible(&parameters)?;
        Ok(Self { parameters, key })
    }

    /// Encrypts an unsigned message in `[0, t)`.
    pub fn encrypt<R>(&self, message: T, rng: &mut R) -> Result<LweCiphertext<T>, ClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        Ok(self.encrypt_with_embedding(message, rng, PlaintextEmbedding::Unsigned))
    }

    /// Encrypts an unsigned message in the programmable front half `[0, ceil(t / 2))`.
    pub fn encrypt_padded<R>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, ClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_padded_message(message)?;
        Ok(self.encrypt_with_embedding(message, rng, PlaintextEmbedding::Unsigned))
    }

    /// Encrypts a centered modular message in `[0, t)`.
    pub fn encrypt_centered<R>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, ClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        Ok(self.encrypt_with_embedding(message, rng, PlaintextEmbedding::Centered))
    }

    /// Encrypts an unsigned message in `[0, t)` into existing storage.
    ///
    /// Overwrites all coefficients without allocating. Message range and output
    /// dimension errors leave both output and RNG unchanged.
    ///
    /// # Correctness
    ///
    /// `output` must contain a body, as required by [`Lwe`].
    ///
    /// # Panics
    ///
    /// A panicking RNG can leave partial output; see
    /// [`primus_lwe::LweSecretKeyRef::encrypt_encoded_to`] and [`primus_lwe::LwePublicKey::encrypt_encoded_to`].
    pub fn encrypt_to<R>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), ClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        self.encrypt_with_embedding_to(message, output, rng, PlaintextEmbedding::Unsigned)
    }

    /// Encrypts a padded message in `[0, ceil(t / 2))` into existing storage.
    ///
    /// Shares [`Self::encrypt_to`]'s storage, error and RNG-panic contracts.
    pub fn encrypt_padded_to<R>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), ClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_padded_message(message)?;
        self.encrypt_with_embedding_to(message, output, rng, PlaintextEmbedding::Unsigned)
    }

    /// Encrypts a centered modular message in `[0, t)` into existing storage.
    ///
    /// Shares [`Self::encrypt_to`]'s storage, error and RNG-panic contracts.
    pub fn encrypt_centered_to<R>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
    ) -> Result<(), ClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        self.encrypt_with_embedding_to(message, output, rng, PlaintextEmbedding::Centered)
    }

    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let plaintext = self.parameters.codec().encode_value(message, embedding);
        self.key.encrypt_encoded(plaintext, &self.parameters, rng)
    }

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: Lwe<&mut [T]>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> Result<(), ClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let expected = self.parameters.dimension();
        let actual = output.dimension();
        if actual != expected.get() {
            return Err(ClientError::CiphertextDimensionMismatch {
                expected: expected.get(),
                actual,
            });
        }
        let plaintext = self.parameters.codec().encode_value(message, embedding);
        self.key
            .encrypt_encoded_to(plaintext, output, &self.parameters, rng);
        Ok(())
    }

    #[inline]
    fn check_padded_message(&self, message: T) -> Result<(), ClientError> {
        let modulus = self.parameters.codec().plaintext_modulus();
        if message >= modulus - (modulus >> 1u32) {
            return Err(if message >= modulus {
                ClientError::MessageOutOfRange
            } else {
                ClientError::MessageOutsidePaddedDomain
            });
        }
        Ok(())
    }

    #[inline]
    fn check_message(&self, message: T) -> Result<(), ClientError> {
        if message >= self.parameters.codec().plaintext_modulus() {
            return Err(ClientError::MessageOutOfRange);
        }
        Ok(())
    }
}

/// Decrypts rounded TFHE messages under a borrowed external LWE secret.
///
/// Inputs are LWE views; use `as_view()` to borrow an owning ciphertext.
pub struct Decryptor<'a, T: FheUint, M: RingContext<T>> {
    codec: &'a RoundedCodec<T, M>,
    key: LweSecretKeyRef<'a, T>,
}

impl<'a, T: FheUint, M: RingContext<T>> Decryptor<'a, T, M> {
    /// Borrows an LWE secret and its message codec.
    ///
    /// # Correctness
    ///
    /// The key's signed or encoded coefficients must satisfy
    /// [`LweSecretKeyRef::decrypt_phase`]'s range contract for the codec's modulus.
    #[must_use]
    pub fn new(codec: &'a RoundedCodec<T, M>, key: LweSecretKeyRef<'a, T>) -> Self {
        Self { codec, key }
    }

    /// Decodes a canonical message in `[0, t)` using the input codec.
    /// For a different LUT output codec, decode [`Self::decrypt_phase`] instead.
    pub fn decrypt(&self, ciphertext: Lwe<&[T]>) -> Result<T, ClientError> {
        let phase = self.decrypt_phase(ciphertext)?;
        Ok(self.codec.decode_value(phase))
    }

    /// Returns the noisy LWE phase as a canonical residue in `[0, q)`.
    ///
    /// # Correctness
    ///
    /// The ciphertext must use this client's external secret and modulus, with
    /// canonical coefficients in `[0, q)`. Only its dimension is checked;
    /// raw ciphertexts carry neither key identity nor encoding metadata.
    pub fn decrypt_phase(&self, ciphertext: Lwe<&[T]>) -> Result<T, ClientError> {
        let expected = self.key.dimension();
        let actual = ciphertext.dimension();
        if actual != expected {
            return Err(ClientError::CiphertextDimensionMismatch { expected, actual });
        }
        Ok(self
            .key
            .decrypt_phase(&ciphertext, self.codec.ciphertext_modulus()))
    }
}
