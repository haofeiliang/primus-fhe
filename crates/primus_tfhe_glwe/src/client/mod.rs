mod encryption_key;

pub use encryption_key::EncryptionKey;

use primus_integer::FheUint;
use primus_lwe::LweSecretKeyRef;
use primus_reduce::RingContext;

use crate::{
    ClientKey, LweCiphertext, PbsOrder, PlaintextEmbedding, TfheClientError, TfheParameters,
};

/// Encrypts raw TFHE messages into LWE ciphertexts with a particular encryption key.
///
/// The LWE and GLWE modulus context types are part of the type, but FFT/NTT
/// tables are not: client-side LWE encryption does not use a transform
/// backend.
///
/// Public-key usage follows [`EncryptionKey`]'s noise and key-identity contracts.
pub struct Encryptor<'a, T, LM, GM, Key = ClientKey<T>>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    parameters: &'a TfheParameters<T, LM, GM>,
    key: &'a Key,
}

impl<'a, T, LM, GM, Key> Encryptor<'a, T, LM, GM, Key>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
    Key: EncryptionKey<T, LM, GM>,
{
    /// Creates an encryptor after checking secret-key parameters or public-key
    /// dimension and modulus. Public-key identity is a caller contract.
    pub fn try_new(
        parameters: &'a TfheParameters<T, LM, GM>,
        key: &'a Key,
    ) -> Result<Self, TfheClientError> {
        EncryptionKey::check_compatible(key, parameters)?;
        Ok(Self { parameters, key })
    }

    /// Encrypts an unsigned message in the range `[0, t)`.
    pub fn encrypt<R>(&self, message: T, rng: &mut R) -> Result<LweCiphertext<T>, TfheClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        Ok(self.encrypt_with_embedding(message, rng, PlaintextEmbedding::Unsigned))
    }

    /// Encrypts a message in the padded domain `[0, ceil(t / 2))`.
    ///
    /// Use this range with front-half LUT compilation; odd full-domain LUTs
    /// accept [`Self::encrypt`]'s entire unsigned domain.
    pub fn encrypt_padded<R>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, TfheClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_padded_message(message)?;
        Ok(self.encrypt_with_embedding(message, rng, PlaintextEmbedding::Unsigned))
    }

    /// Encrypts a centered modular message in the range `[0, t)`.
    ///
    /// Values in the upper half of the plaintext domain represent negative
    /// values. For example, `3` represents `-1` when `t = 4`.
    pub fn encrypt_centered<R>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, TfheClientError>
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
    /// `output` must contain a body, as required by [`LweCiphertext`].
    ///
    /// # Panics
    ///
    /// A panicking RNG can leave partial output; see
    /// [`LweSecretKeyRef::encrypt_encoded_to`] and [`primus_lwe::LwePublicKey::encrypt_encoded_to`].
    pub fn encrypt_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), TfheClientError>
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
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), TfheClientError>
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
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), TfheClientError>
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
        let plaintext = self
            .parameters
            .input_plaintext_codec()
            .encode_value(message, embedding);
        self.key.encrypt_encoded(plaintext, self.parameters, rng)
    }

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> Result<(), TfheClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let expected = self.parameters.external_lwe_dimension();
        let actual = output.dimension();
        if actual != expected {
            return Err(TfheClientError::CiphertextDimensionMismatch { expected, actual });
        }
        let plaintext = self
            .parameters
            .input_plaintext_codec()
            .encode_value(message, embedding);
        self.key
            .encrypt_encoded_to(plaintext, output, self.parameters, rng);
        Ok(())
    }

    #[inline]
    fn check_padded_message(&self, message: T) -> Result<(), TfheClientError> {
        let modulus = self.parameters.plain_modulus_value();
        if message >= modulus - (modulus >> 1u32) {
            return Err(if message >= modulus {
                TfheClientError::MessageOutOfRange
            } else {
                TfheClientError::MessageOutsidePaddedDomain
            });
        }
        Ok(())
    }

    #[inline]
    fn check_message(&self, message: T) -> Result<(), TfheClientError> {
        if message >= self.parameters.plain_modulus_value() {
            return Err(TfheClientError::MessageOutOfRange);
        }
        Ok(())
    }
}

/// Decrypts raw TFHE ciphertexts with the client key.
pub struct Decryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    parameters: &'a TfheParameters<T, LM, GM>,
    key: &'a ClientKey<T>,
}

impl<'a, T, LM, GM> Decryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates a decryptor after checking key compatibility.
    pub fn try_new(
        parameters: &'a TfheParameters<T, LM, GM>,
        key: &'a ClientKey<T>,
    ) -> Result<Self, TfheClientError> {
        key.check_compatible(parameters)?;
        Ok(Self { parameters, key })
    }

    /// Decrypts using the parameter codec to a canonical message in `[0, t)`.
    /// For a different LUT output codec, decode [`Self::decrypt_phase`] instead.
    pub fn decrypt(&self, ciphertext: &LweCiphertext<T>) -> Result<T, TfheClientError> {
        let phase = self.decrypt_phase(ciphertext)?;
        Ok(self.parameters.input_plaintext_codec().decode_value(phase))
    }

    /// Returns the noisy LWE phase as a canonical residue in `[0, q)`.
    ///
    /// Uses the external client secret and ciphertext modulus, without message
    /// decoding. For ordinary PBS output, pass the phase to the LUT's output codec.
    ///
    /// # Correctness
    ///
    /// The ciphertext must use this client's external secret and modulus, with
    /// canonical coefficients in `[0, q)`. Only its dimension is checked;
    /// the ciphertext does not carry encoding metadata.
    pub fn decrypt_phase(&self, ciphertext: &LweCiphertext<T>) -> Result<T, TfheClientError> {
        let expected = self.parameters.external_lwe_dimension();
        let actual = ciphertext.dimension();
        if actual != expected {
            return Err(TfheClientError::CiphertextDimensionMismatch { expected, actual });
        }
        let phase = match self.parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => self
                .key
                .small_lwe_secret_key()
                .as_view()
                .decrypt_phase(ciphertext, self.parameters.small_lwe().cipher_modulus()),
            PbsOrder::KeyswitchBootstrap => {
                LweSecretKeyRef::Signed(self.key.glwe_secret_key().as_slice()).decrypt_phase(
                    ciphertext,
                    self.parameters.accumulator_glwe().cipher_modulus(),
                )
            }
        };
        Ok(phase)
    }
}
