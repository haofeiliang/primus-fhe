use primus_integer::FheUint;
use primus_lwe::LweSecretKeyRef;
use primus_reduce::RingContext;

use crate::{
    GlweClientKey, GlweKeyError, GlwePbsOrder, GlweTfheParameters, LweCiphertext,
    PlaintextEmbedding,
};

/// Encrypts raw TFHE messages with a particular encryption key.
///
/// The LWE and GLWE modulus context types are part of the type, but FFT/NTT
/// tables are not: client-side LWE encryption does not use a transform
/// backend.
pub struct GlweEncryptor<'a, T, LM, GM, Key>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    parameters: &'a GlweTfheParameters<T, LM, GM>,
    key: &'a Key,
}

impl<'a, T, LM, GM> GlweEncryptor<'a, T, LM, GM, GlweClientKey<T>>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates a secret-key encryptor after checking key compatibility.
    pub fn with_client_key(
        parameters: &'a GlweTfheParameters<T, LM, GM>,
        key: &'a GlweClientKey<T>,
    ) -> Result<Self, GlweClientError> {
        key.check_compatible(parameters)?;
        Ok(Self { parameters, key })
    }

    /// Encrypts an unsigned message in the range `[0, t)`.
    pub fn encrypt<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        Ok(self.encrypt_with_embedding(message, PlaintextEmbedding::Unsigned, rng))
    }

    /// Encrypts a message in the padded domain `[0, ceil(t / 2))`.
    ///
    /// This preserves the input-padding invariant required by an arbitrary
    /// (not necessarily negacyclic) programmable-bootstrap lookup table.
    pub fn encrypt_padded<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        let modulus = self.parameters.plain_modulus_value();
        let front_domain_len = modulus - (modulus >> 1u32);
        if message >= front_domain_len {
            return Err(GlweClientError::MessageOutsidePaddedDomain);
        }
        Ok(self.encrypt_with_embedding(message, PlaintextEmbedding::Unsigned, rng))
    }

    /// Encrypts a centered modular message in the range `[0, t)`.
    ///
    /// Values in the upper half of the plaintext domain represent negative
    /// values. For example, `3` represents `-1` when `t = 4`.
    pub fn encrypt_centered<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        Ok(self.encrypt_with_embedding(message, PlaintextEmbedding::Centered, rng))
    }

    #[inline]
    fn checked_message<Msg>(&self, message: Msg) -> Result<T, GlweClientError>
    where
        Msg: TryInto<T>,
    {
        let message = message
            .try_into()
            .map_err(|_| GlweClientError::MessageConversion)?;
        if message >= self.parameters.plain_modulus_value() {
            return Err(GlweClientError::MessageOutOfRange);
        }
        Ok(message)
    }

    #[inline]
    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        match self.parameters.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => {
                let parameters = self.parameters.small_lwe();
                self.key
                    .small_lwe_secret_key()
                    .encrypt_with_embedding(message, parameters, rng, embedding)
            }
            GlwePbsOrder::KeyswitchBootstrap => {
                // TFHE construction validates equal t and q for both key domains.
                let parameters = self.parameters.glwe();
                let plaintext = self
                    .parameters
                    .small_lwe()
                    .plaintext_codec()
                    .encode_value(message, embedding);
                LweSecretKeyRef::Signed(self.key.glwe_secret_key().as_slice()).encrypt_encoded(
                    plaintext,
                    parameters.cipher_modulus(),
                    parameters.cipher_modulus_uniform_distr(),
                    parameters.noise_distribution(),
                    rng,
                )
            }
        }
    }
}

/// Decrypts raw TFHE ciphertexts with the client key.
pub struct GlweDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    parameters: &'a GlweTfheParameters<T, LM, GM>,
    key: &'a GlweClientKey<T>,
}

impl<'a, T, LM, GM> GlweDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates a decryptor after checking key compatibility.
    pub fn new(
        parameters: &'a GlweTfheParameters<T, LM, GM>,
        key: &'a GlweClientKey<T>,
    ) -> Result<Self, GlweClientError> {
        key.check_compatible(parameters)?;
        Ok(Self { parameters, key })
    }

    /// Decrypts to the canonical representative in `[0, t)`.
    pub fn decrypt<Msg>(&self, ciphertext: &LweCiphertext<T>) -> Result<Msg, GlweClientError>
    where
        Msg: TryFrom<T>,
    {
        let expected = self.parameters.ciphertext_lwe_dimension();
        let actual = ciphertext.dimension();
        if actual != expected {
            return Err(GlweClientError::CiphertextDimensionMismatch { expected, actual });
        }

        let message: T = match self.parameters.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => {
                let parameters = self.parameters.small_lwe();
                self.key
                    .small_lwe_secret_key()
                    .decrypt(ciphertext, parameters)
            }
            GlwePbsOrder::KeyswitchBootstrap => {
                // TFHE construction validates equal t and q for both key domains.
                let parameters = self.parameters.glwe();
                let phase = LweSecretKeyRef::Signed(self.key.glwe_secret_key().as_slice())
                    .decrypt_phase(ciphertext, parameters.cipher_modulus());
                self.parameters
                    .small_lwe()
                    .plaintext_codec()
                    .decode_value(phase)
            }
        };
        Msg::try_from(message).map_err(|_| GlweClientError::PlaintextConversion)
    }
}

/// An error produced by the raw TFHE client API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlweClientError {
    /// The client key does not match the parameter set.
    #[error(transparent)]
    IncompatibleKey(#[from] GlweKeyError),

    /// The input message cannot be represented by the ciphertext integer type.
    #[error("message cannot be represented by the ciphertext integer type")]
    MessageConversion,

    /// The input message is outside the plaintext domain `[0, t)`.
    #[error("message is outside the plaintext domain")]
    MessageOutOfRange,

    /// The input message sets the padding half of the plaintext domain.
    #[error("message is outside the padded plaintext domain")]
    MessageOutsidePaddedDomain,

    /// A ciphertext belongs to a different LWE dimension.
    #[error("LWE ciphertext dimension mismatch: expected {expected}, got {actual}")]
    CiphertextDimensionMismatch {
        /// Required LWE dimension.
        expected: usize,
        /// Actual LWE dimension.
        actual: usize,
    },

    /// The decrypted representative cannot be converted to the requested type.
    #[error("plaintext cannot be represented by the requested output type")]
    PlaintextConversion,
}
