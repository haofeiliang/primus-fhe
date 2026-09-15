use primus_integer::FheUint;
use primus_lwe::{LwePublicKey, LweSecretKeyRef};
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
///
/// Public-key usage follows [`GlweEncryptionKey`]'s noise and key-identity contracts.
pub struct GlweEncryptor<'a, T, LM, GM, Key = GlweClientKey<T>>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    parameters: &'a GlweTfheParameters<T, LM, GM>,
    key: &'a Key,
}

impl<'a, T, LM, GM, Key> GlweEncryptor<'a, T, LM, GM, Key>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
    Key: GlweEncryptionKey<T, LM, GM>,
{
    /// Creates an encryptor after checking secret-key parameters or public-key
    /// dimension and modulus. Public-key identity is a caller contract.
    pub fn try_new(
        parameters: &'a GlweTfheParameters<T, LM, GM>,
        key: &'a Key,
    ) -> Result<Self, GlweClientError> {
        GlweEncryptionKey::check_compatible(key, parameters)?;
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
        Ok(self.key.encrypt_with_embedding(
            message,
            self.parameters,
            rng,
            PlaintextEmbedding::Unsigned,
        ))
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
        Ok(self.key.encrypt_with_embedding(
            message,
            self.parameters,
            rng,
            PlaintextEmbedding::Unsigned,
        ))
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
        Ok(self.key.encrypt_with_embedding(
            message,
            self.parameters,
            rng,
            PlaintextEmbedding::Centered,
        ))
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
}

mod sealed {
    pub trait Sealed {}
    impl<T: primus_integer::FheUint> Sealed for super::GlweClientKey<T> {}
    impl<T: primus_integer::FheUint> Sealed for primus_lwe::LwePublicKey<T> {}
}

/// Supported secret and public keys for [`GlweEncryptor`].
///
/// Implemented only for [`GlweClientKey`] and [`LwePublicKey`]. A public key
/// must come from the external client secret paired with the server key;
/// matching dimensions and moduli cannot establish that relationship.
/// Public encryption uses the external secret-encryption noise sampler for
/// each fresh error term. The combined noise must satisfy [`LwePublicKey`]'s
/// correctness requirements and the PBS/ManyLUT input noise budget.
pub trait GlweEncryptionKey<T, LM, GM>: sealed::Sealed
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Checks the structural compatibility needed by the encryptor constructor.
    fn check_compatible(
        &self,
        parameters: &GlweTfheParameters<T, LM, GM>,
    ) -> Result<(), GlweClientError>;

    /// Encrypts with the configured external encoding and noise samplers.
    ///
    /// # Correctness
    ///
    /// Requires successful [`Self::check_compatible`] and the type's secret,
    /// public-key noise and key-identity contracts. Signed/encoded secret ranges
    /// follow [`LweSecretKeyRef`].
    ///
    /// # Panics
    ///
    /// Panics if `message` is outside `[0, t)`.
    #[must_use]
    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        parameters: &GlweTfheParameters<T, LM, GM>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng;
}

impl<T, LM, GM> GlweEncryptionKey<T, LM, GM> for GlweClientKey<T>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    fn check_compatible(
        &self,
        parameters: &GlweTfheParameters<T, LM, GM>,
    ) -> Result<(), GlweClientError> {
        Ok(self.check_compatible(parameters)?)
    }

    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        parameters: &GlweTfheParameters<T, LM, GM>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        match parameters.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => {
                let parameters = parameters.small_lwe();
                self.small_lwe_secret_key()
                    .encrypt_with_embedding(message, parameters, rng, embedding)
            }
            GlwePbsOrder::KeyswitchBootstrap => {
                // TFHE construction validates equal t and q for both key domains.
                let plaintext = parameters
                    .small_lwe()
                    .plaintext_codec()
                    .encode_value(message, embedding);
                let parameters = parameters.glwe();
                LweSecretKeyRef::Signed(self.glwe_secret_key().as_slice()).encrypt_encoded(
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

impl<T, LM, GM> GlweEncryptionKey<T, LM, GM> for LwePublicKey<T>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    fn check_compatible(
        &self,
        parameters: &GlweTfheParameters<T, LM, GM>,
    ) -> Result<(), GlweClientError> {
        if self.dimension() != parameters.ciphertext_lwe_dimension() {
            return Err(GlweClientError::PublicKeyDimensionMismatch {
                expected: parameters.ciphertext_lwe_dimension(),
                actual: self.dimension(),
            });
        }
        if self.cipher_modulus_minus_one() != parameters.small_lwe().cipher_modulus_minus_one() {
            return Err(GlweClientError::PublicKeyModulusMismatch);
        }
        Ok(())
    }

    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        parameters: &GlweTfheParameters<T, LM, GM>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.small_lwe();
        let plaintext = lwe.plaintext_codec().encode_value(message, embedding);
        let noise = match parameters.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => lwe.noise_distribution(),
            GlwePbsOrder::KeyswitchBootstrap => parameters.glwe().noise_distribution(),
        };
        self.encrypt_encoded(plaintext, lwe.cipher_modulus(), noise, rng)
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
    pub fn try_new(
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
    /// The public key has the wrong external LWE dimension.
    #[error("public-key LWE dimension mismatch: expected {expected}, got {actual}")]
    PublicKeyDimensionMismatch {
        /// Required external LWE dimension.
        expected: usize,
        /// Supplied public-key dimension.
        actual: usize,
    },
    /// The public key uses a different ciphertext modulus.
    #[error("public-key ciphertext modulus mismatch")]
    PublicKeyModulusMismatch,
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
