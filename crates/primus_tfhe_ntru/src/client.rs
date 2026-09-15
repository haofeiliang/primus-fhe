use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_lwe::{LweCiphertext, LwePublicKey, LweSecretKeyRef};
use primus_reduce::RingContext;

use crate::{NtruClientKey, NtruKeyError, NtruTfheParameters};

/// Encrypts external LWE messages with a client secret key or [`LwePublicKey`].
///
/// Public-key usage follows [`NtruEncryptionKey`]'s noise and key-identity contracts.
pub struct NtruEncryptor<'a, T, M, Key = NtruClientKey<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters: &'a NtruTfheParameters<T, M>,
    key: &'a Key,
}

impl<'a, T, M, Key> NtruEncryptor<'a, T, M, Key>
where
    T: FheUint,
    M: RingContext<T>,
    Key: NtruEncryptionKey<T, M>,
{
    /// Creates an encryptor after checking secret-key parameters or public-key
    /// dimension and modulus. Public-key identity is a caller contract.
    pub fn try_new(
        parameters: &'a NtruTfheParameters<T, M>,
        key: &'a Key,
    ) -> Result<Self, NtruClientError> {
        NtruEncryptionKey::check_compatible(key, parameters)?;
        Ok(Self { parameters, key })
    }

    /// Encrypts an unsigned message in `[0, t)`.
    pub fn encrypt<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, NtruClientError>
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

    /// Encrypts an unsigned message in the programmable front half `[0, ceil(t / 2))`.
    pub fn encrypt_padded<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, NtruClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_padded_message(message)?;
        Ok(self.key.encrypt_with_embedding(
            message,
            self.parameters,
            rng,
            PlaintextEmbedding::Unsigned,
        ))
    }

    /// Encrypts a centered modular message in `[0, t)`.
    pub fn encrypt_centered<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, NtruClientError>
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

    /// Encrypts an unsigned message in `[0, t)` into existing storage.
    ///
    /// Overwrites all coefficients without allocating. Message conversion,
    /// range and output dimension errors leave both output and RNG unchanged.
    ///
    /// # Correctness
    ///
    /// `output` must contain a body, as required by [`LweCiphertext`].
    ///
    /// # Panics
    ///
    /// A panicking RNG can leave partial output; see
    /// [`LweSecretKeyRef::encrypt_encoded_to`] and [`LwePublicKey::encrypt_encoded_to`].
    pub fn encrypt_to<R, Msg>(
        &self,
        message: Msg,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), NtruClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        self.encrypt_with_embedding_to(message, output, rng, PlaintextEmbedding::Unsigned)
    }

    /// Encrypts a padded message in `[0, ceil(t / 2))` into existing storage.
    ///
    /// Shares [`Self::encrypt_to`]'s storage, error and RNG-panic contracts.
    pub fn encrypt_padded_to<R, Msg>(
        &self,
        message: Msg,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), NtruClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_padded_message(message)?;
        self.encrypt_with_embedding_to(message, output, rng, PlaintextEmbedding::Unsigned)
    }

    /// Encrypts a centered modular message in `[0, t)` into existing storage.
    ///
    /// Shares [`Self::encrypt_to`]'s storage, error and RNG-panic contracts.
    pub fn encrypt_centered_to<R, Msg>(
        &self,
        message: Msg,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), NtruClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        self.encrypt_with_embedding_to(message, output, rng, PlaintextEmbedding::Centered)
    }

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> Result<(), NtruClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let expected = self.parameters.external_lwe().dimension();
        let actual = output.dimension();
        if actual != expected {
            return Err(NtruClientError::CiphertextDimensionMismatch { expected, actual });
        }
        self.key
            .encrypt_with_embedding_to(message, output, self.parameters, rng, embedding);
        Ok(())
    }

    #[inline]
    fn checked_padded_message<Msg>(&self, message: Msg) -> Result<T, NtruClientError>
    where
        Msg: TryInto<T>,
    {
        let message = message
            .try_into()
            .map_err(|_| NtruClientError::MessageConversion)?;
        let modulus = self.parameters.plain_modulus_value();
        if message >= modulus - (modulus >> 1u32) {
            return Err(if message >= modulus {
                NtruClientError::MessageOutOfRange
            } else {
                NtruClientError::MessageOutsidePaddedDomain
            });
        }
        Ok(message)
    }

    /// Converts and range-checks one client message.
    #[inline]
    fn checked_message<Msg>(&self, message: Msg) -> Result<T, NtruClientError>
    where
        Msg: TryInto<T>,
    {
        let message = message
            .try_into()
            .map_err(|_| NtruClientError::MessageConversion)?;
        if message >= self.parameters.plain_modulus_value() {
            return Err(NtruClientError::MessageOutOfRange);
        }
        Ok(message)
    }
}

mod sealed {
    pub trait Sealed {}
    impl<T: primus_integer::FheUint> Sealed for super::NtruClientKey<T> {}
    impl<T: primus_integer::FheUint> Sealed for primus_lwe::LwePublicKey<T> {}
}

/// Supported secret and public keys for [`NtruEncryptor`].
///
/// Implemented only for [`NtruClientKey`] and [`LwePublicKey`]. A public key
/// must come from the external client secret paired with the server key;
/// matching dimensions and moduli cannot establish that relationship.
/// Public encryption uses the external secret-encryption noise sampler for
/// each fresh error term. The combined noise must satisfy [`LwePublicKey`]'s
/// correctness requirements and the PBS/ManyLUT input noise budget.
pub trait NtruEncryptionKey<T, M>: sealed::Sealed
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Checks the structural compatibility needed by the encryptor constructor.
    fn check_compatible(
        &self,
        parameters: &NtruTfheParameters<T, M>,
    ) -> Result<(), NtruClientError>;

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
        parameters: &NtruTfheParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng;

    /// Overwrites caller storage with the configured encoding and noise samplers.
    ///
    /// # Correctness
    ///
    /// Inherits [`Self::encrypt_with_embedding`]'s parameter and key contracts.
    ///
    /// # Panics
    ///
    /// Panics for a message outside `[0, t)` or an incompatible output length.
    /// RNG panics may leave partial output; see [`LweSecretKeyRef::encrypt_encoded_to`]
    /// and [`LwePublicKey::encrypt_encoded_to`].
    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        parameters: &NtruTfheParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng;
}

impl<T, M> NtruEncryptionKey<T, M> for NtruClientKey<T>
where
    T: FheUint,
    M: RingContext<T>,
{
    fn check_compatible(
        &self,
        parameters: &NtruTfheParameters<T, M>,
    ) -> Result<(), NtruClientError> {
        Ok(self.check_compatible(parameters)?)
    }

    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        parameters: &NtruTfheParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = parameters.external_lwe();
        let plaintext = parameters
            .plaintext_codec()
            .encode_value(message, embedding);
        LweSecretKeyRef::Signed(self.external_lwe_secret_key()).encrypt_encoded(
            plaintext,
            parameters.cipher_modulus(),
            parameters.cipher_modulus_uniform_distr(),
            parameters.noise_distribution(),
            rng,
        )
    }

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        parameters: &NtruTfheParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.external_lwe();
        let plaintext = lwe.plaintext_codec().encode_value(message, embedding);
        LweSecretKeyRef::Signed(self.external_lwe_secret_key()).encrypt_encoded_to(
            plaintext,
            output,
            lwe.cipher_modulus(),
            lwe.cipher_modulus_uniform_distr(),
            lwe.noise_distribution(),
            rng,
        );
    }
}

impl<T, M> NtruEncryptionKey<T, M> for LwePublicKey<T>
where
    T: FheUint,
    M: RingContext<T>,
{
    fn check_compatible(
        &self,
        parameters: &NtruTfheParameters<T, M>,
    ) -> Result<(), NtruClientError> {
        if self.dimension() != parameters.external_lwe().dimension() {
            return Err(NtruClientError::PublicKeyDimensionMismatch {
                expected: parameters.external_lwe().dimension(),
                actual: self.dimension(),
            });
        }
        if self.cipher_modulus_minus_one() != parameters.external_lwe().cipher_modulus_minus_one() {
            return Err(NtruClientError::PublicKeyModulusMismatch);
        }
        Ok(())
    }

    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        parameters: &NtruTfheParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.external_lwe();
        let plaintext = lwe.plaintext_codec().encode_value(message, embedding);
        self.encrypt_encoded(
            plaintext,
            lwe.cipher_modulus(),
            lwe.noise_distribution(),
            rng,
        )
    }

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        parameters: &NtruTfheParameters<T, M>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.external_lwe();
        let plaintext = lwe.plaintext_codec().encode_value(message, embedding);
        self.encrypt_encoded_to(
            plaintext,
            output,
            lwe.cipher_modulus(),
            lwe.noise_distribution(),
            rng,
        );
    }
}

/// Decrypts external LWE ciphertexts under the client NTRU coefficients.
pub struct NtruDecryptor<'a, T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters: &'a NtruTfheParameters<T, M>,
    key: &'a NtruClientKey<T>,
}

impl<'a, T, M> NtruDecryptor<'a, T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a decryptor after checking client-key compatibility.
    pub fn try_new(
        parameters: &'a NtruTfheParameters<T, M>,
        key: &'a NtruClientKey<T>,
    ) -> Result<Self, NtruClientError> {
        key.check_compatible(parameters)?;
        Ok(Self { parameters, key })
    }

    /// Decrypts to the canonical representative in `[0, t)`.
    pub fn decrypt<Msg>(&self, ciphertext: &LweCiphertext<T>) -> Result<Msg, NtruClientError>
    where
        Msg: TryFrom<T>,
    {
        let expected = self.parameters.external_lwe().dimension();
        let actual = ciphertext.dimension();
        if actual != expected {
            return Err(NtruClientError::CiphertextDimensionMismatch { expected, actual });
        }
        let parameters = self.parameters.external_lwe();
        let phase = LweSecretKeyRef::Signed(self.key.external_lwe_secret_key())
            .decrypt_phase(ciphertext, parameters.cipher_modulus());
        let message = parameters.plaintext_codec().decode_value(phase);
        Msg::try_from(message).map_err(|_| NtruClientError::PlaintextConversion)
    }
}

/// An error produced by the NTRU TFHE client API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NtruClientError {
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
    IncompatibleKey(#[from] NtruKeyError),
    /// The message cannot be represented by the ciphertext integer type.
    #[error("message cannot be represented by the ciphertext integer type")]
    MessageConversion,
    /// The message is outside `[0, t)`.
    #[error("message is outside the plaintext domain")]
    MessageOutOfRange,
    /// The message violates the input-padding convention.
    #[error("message is outside the programmable padded domain")]
    MessageOutsidePaddedDomain,
    /// The ciphertext has the wrong LWE dimension.
    #[error("ciphertext LWE dimension mismatch: expected {expected}, got {actual}")]
    CiphertextDimensionMismatch {
        /// Expected external LWE dimension.
        expected: usize,
        /// Supplied LWE dimension.
        actual: usize,
    },
    /// The decoded word cannot be converted to the requested type.
    #[error("decoded plaintext cannot be converted to the requested type")]
    PlaintextConversion,
}
