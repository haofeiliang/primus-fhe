use primus_distr::DiscreteGaussian;
use primus_integer::{FheUint, SignedInteger};
use primus_reduce::RingContext;
use primus_tfhe::Ciphertext;
use rand::distr::{Distribution, Uniform};

use crate::{
    GlweClientKey, GlweKeyError, GlwePbsOrder, GlweTfheParameters, LweCiphertext, PlaintextCodec,
    PlaintextEmbedding, SecretCoefficient, encode_secret_coefficient,
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
    ) -> Result<Ciphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        Ok(Ciphertext::from_lwe(self.encrypt_with_embedding(
            message,
            PlaintextEmbedding::Unsigned,
            rng,
        )))
    }

    /// Encrypts a message in the padded domain `[0, floor(t / 2))`.
    ///
    /// This preserves the input-padding invariant required by an arbitrary
    /// (not necessarily negacyclic) programmable-bootstrap lookup table.
    pub fn encrypt_padded<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<Ciphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        let modulus = self.parameters.plain_modulus_value();
        let front_domain_len = modulus >> 1u32;
        if message >= front_domain_len {
            return Err(GlweClientError::MessageOutsidePaddedDomain);
        }
        Ok(Ciphertext::from_lwe(self.encrypt_with_embedding(
            message,
            PlaintextEmbedding::Unsigned,
            rng,
        )))
    }

    /// Encrypts a centered modular message in the range `[0, t)`.
    ///
    /// Values in the upper half of the plaintext domain represent negative
    /// values. For example, `3` represents `-1` when `t = 4`.
    pub fn encrypt_centered<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<Ciphertext<T>, GlweClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        Ok(Ciphertext::from_lwe(self.encrypt_with_embedding(
            message,
            PlaintextEmbedding::Centered,
            rng,
        )))
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
                encrypt_lwe_with_secret(
                    self.key.small_lwe_secret_key().as_ref(),
                    message,
                    parameters.cipher_modulus(),
                    parameters.cipher_modulus_uniform_distr(),
                    parameters.noise_distribution(),
                    parameters.plaintext_codec(),
                    embedding,
                    rng,
                )
            }
            GlwePbsOrder::KeyswitchBootstrap => {
                let parameters = self.parameters.glwe();
                encrypt_lwe_with_signed_secret(
                    self.key.glwe_secret_key().as_slice(),
                    message,
                    parameters.cipher_modulus(),
                    parameters.cipher_modulus_uniform_distr(),
                    parameters.noise_distribution(),
                    parameters.plaintext_codec(),
                    embedding,
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
    pub fn decrypt<Msg>(&self, ciphertext: &Ciphertext<T>) -> Result<Msg, GlweClientError>
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
                decrypt_lwe_with_secret(
                    self.key.small_lwe_secret_key().as_ref(),
                    ciphertext.as_lwe(),
                    parameters.cipher_modulus(),
                    parameters.plaintext_codec(),
                )
            }
            GlwePbsOrder::KeyswitchBootstrap => {
                let parameters = self.parameters.glwe();
                decrypt_lwe_with_signed_secret(
                    self.key.glwe_secret_key().as_slice(),
                    ciphertext.as_lwe(),
                    parameters.cipher_modulus(),
                    parameters.plaintext_codec(),
                )
            }
        };
        Msg::try_from(message).map_err(|_| GlweClientError::PlaintextConversion)
    }
}

#[allow(clippy::too_many_arguments)]
fn encrypt_lwe_with_secret<T, M, R>(
    secret_key: &[T],
    message: T,
    modulus: M,
    uniform: Uniform<T>,
    gaussian: &DiscreteGaussian<T>,
    codec: &PlaintextCodec<T>,
    embedding: PlaintextEmbedding,
    rng: &mut R,
) -> LweCiphertext<T>
where
    T: FheUint,
    M: RingContext<T>,
    R: rand::Rng + rand::CryptoRng,
{
    let mut ciphertext =
        LweCiphertext::generate_random_zero_sample(secret_key, modulus, uniform, gaussian, rng);
    codec.add_encode_value(ciphertext.b_mut(), message, embedding);
    ciphertext
}

fn decrypt_lwe_with_secret<T, M>(
    secret_key: &[T],
    ciphertext: &LweCiphertext<T>,
    modulus: M,
    codec: &PlaintextCodec<T>,
) -> T
where
    T: FheUint,
    M: RingContext<T>,
{
    let (mask, body) = ciphertext.a_b();
    debug_assert_eq!(mask.len(), secret_key.len());
    let plaintext = modulus.reduce_sub(body, modulus.reduce_dot_product(mask, secret_key));
    codec.decode_value(plaintext)
}

#[allow(clippy::too_many_arguments)]
fn encrypt_lwe_with_signed_secret<T, M, R>(
    secret_key: &[SecretCoefficient<T>],
    message: T,
    modulus: M,
    uniform: Uniform<T>,
    gaussian: &DiscreteGaussian<T>,
    codec: &PlaintextCodec<T>,
    embedding: PlaintextEmbedding,
    rng: &mut R,
) -> LweCiphertext<T>
where
    T: FheUint,
    M: RingContext<T>,
    R: rand::Rng + rand::CryptoRng,
{
    let mut ciphertext = LweCiphertext::zero(secret_key.len());
    ciphertext
        .a_mut()
        .iter_mut()
        .zip(uniform.sample_iter(&mut *rng))
        .for_each(|(output, sample)| *output = sample);
    let dot_product = modulus.reduce_dot_product_iter(
        ciphertext.a().iter().copied(),
        secret_key
            .iter()
            .copied()
            .map(|coefficient| encode_for_ring(coefficient, modulus)),
    );
    *ciphertext.b_mut() = modulus.reduce_add(dot_product, gaussian.sample(rng));
    codec.add_encode_value(ciphertext.b_mut(), message, embedding);
    ciphertext
}

fn decrypt_lwe_with_signed_secret<T, M>(
    secret_key: &[SecretCoefficient<T>],
    ciphertext: &LweCiphertext<T>,
    modulus: M,
    codec: &PlaintextCodec<T>,
) -> T
where
    T: FheUint,
    M: RingContext<T>,
{
    let (mask, body) = ciphertext.a_b();
    debug_assert_eq!(mask.len(), secret_key.len());
    let dot_product = modulus.reduce_dot_product_iter(
        mask.iter().copied(),
        secret_key
            .iter()
            .copied()
            .map(|coefficient| encode_for_ring(coefficient, modulus)),
    );
    codec.decode_value(modulus.reduce_sub(body, dot_product))
}

#[inline]
fn encode_for_ring<T, M>(coefficient: SecretCoefficient<T>, modulus: M) -> T
where
    T: FheUint,
    M: RingContext<T>,
{
    match modulus.explicit_value() {
        Some(modulus) => encode_secret_coefficient(coefficient, modulus),
        None => coefficient.cast_to_unsigned(),
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
