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
    pub fn encrypt<R>(&self, message: T, rng: &mut R) -> Result<LweCiphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        Ok(self.key.encrypt_with_embedding(
            message,
            self.parameters,
            rng,
            PlaintextEmbedding::Unsigned,
        ))
    }

    /// Encrypts a message in the padded domain `[0, ceil(t / 2))`.
    ///
    /// Use this range with front-half LUT compilation; odd full-domain LUTs
    /// accept [`Self::encrypt`]'s entire unsigned domain.
    pub fn encrypt_padded<R>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_padded_message(message)?;
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
    pub fn encrypt_centered<R>(
        &self,
        message: T,
        rng: &mut R,
    ) -> Result<LweCiphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        Ok(self.key.encrypt_with_embedding(
            message,
            self.parameters,
            rng,
            PlaintextEmbedding::Centered,
        ))
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
    /// [`LweSecretKeyRef::encrypt_encoded_to`] and [`LwePublicKey::encrypt_encoded_to`].
    pub fn encrypt_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), GlweClientError>
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
    ) -> Result<(), GlweClientError>
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
    ) -> Result<(), GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_message(message)?;
        self.encrypt_with_embedding_to(message, output, rng, PlaintextEmbedding::Centered)
    }

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) -> Result<(), GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let expected = self.parameters.ciphertext_lwe_dimension();
        let actual = output.dimension();
        if actual != expected {
            return Err(GlweClientError::CiphertextDimensionMismatch { expected, actual });
        }
        self.key
            .encrypt_with_embedding_to(message, output, self.parameters, rng, embedding);
        Ok(())
    }

    #[inline]
    fn check_padded_message(&self, message: T) -> Result<(), GlweClientError> {
        let modulus = self.parameters.plain_modulus_value();
        if message >= modulus - (modulus >> 1u32) {
            return Err(if message >= modulus {
                GlweClientError::MessageOutOfRange
            } else {
                GlweClientError::MessageOutsidePaddedDomain
            });
        }
        Ok(())
    }

    #[inline]
    fn check_message(&self, message: T) -> Result<(), GlweClientError> {
        if message >= self.parameters.plain_modulus_value() {
            return Err(GlweClientError::MessageOutOfRange);
        }
        Ok(())
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
        parameters: &GlweTfheParameters<T, LM, GM>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
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

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        parameters: &GlweTfheParameters<T, LM, GM>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.small_lwe();
        let plaintext = lwe.plaintext_codec().encode_value(message, embedding);
        match parameters.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => {
                self.small_lwe_secret_key().as_view().encrypt_encoded_to(
                    plaintext,
                    output,
                    lwe.cipher_modulus(),
                    lwe.cipher_modulus_uniform_distr(),
                    lwe.noise_distribution(),
                    rng,
                )
            }
            GlwePbsOrder::KeyswitchBootstrap => {
                let glwe = parameters.glwe();
                LweSecretKeyRef::Signed(self.glwe_secret_key().as_slice()).encrypt_encoded_to(
                    plaintext,
                    output,
                    glwe.cipher_modulus(),
                    glwe.cipher_modulus_uniform_distr(),
                    glwe.noise_distribution(),
                    rng,
                );
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

    fn encrypt_with_embedding_to<R>(
        &self,
        message: T,
        output: &mut LweCiphertext<T>,
        parameters: &GlweTfheParameters<T, LM, GM>,
        rng: &mut R,
        embedding: PlaintextEmbedding,
    ) where
        R: rand::Rng + rand::CryptoRng,
    {
        let lwe = parameters.small_lwe();
        let plaintext = lwe.plaintext_codec().encode_value(message, embedding);
        let noise = match parameters.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => lwe.noise_distribution(),
            GlwePbsOrder::KeyswitchBootstrap => parameters.glwe().noise_distribution(),
        };
        self.encrypt_encoded_to(plaintext, output, lwe.cipher_modulus(), noise, rng);
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

    /// Decrypts using the parameter codec to a canonical message in `[0, t)`.
    /// For a different LUT output codec, decode [`Self::decrypt_phase`] instead.
    pub fn decrypt(&self, ciphertext: &LweCiphertext<T>) -> Result<T, GlweClientError> {
        let phase = self.decrypt_phase(ciphertext)?;
        Ok(self
            .parameters
            .small_lwe()
            .plaintext_codec()
            .decode_value(phase))
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
    pub fn decrypt_phase(&self, ciphertext: &LweCiphertext<T>) -> Result<T, GlweClientError> {
        let expected = self.parameters.ciphertext_lwe_dimension();
        let actual = ciphertext.dimension();
        if actual != expected {
            return Err(GlweClientError::CiphertextDimensionMismatch { expected, actual });
        }
        let phase = match self.parameters.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => self
                .key
                .small_lwe_secret_key()
                .as_view()
                .decrypt_phase(ciphertext, self.parameters.small_lwe().cipher_modulus()),
            GlwePbsOrder::KeyswitchBootstrap => {
                LweSecretKeyRef::Signed(self.key.glwe_secret_key().as_slice())
                    .decrypt_phase(ciphertext, self.parameters.glwe().cipher_modulus())
            }
        };
        Ok(phase)
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
}
