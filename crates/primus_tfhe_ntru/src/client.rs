use num_traits::Signed;
use primus_distr::DiscreteGaussian;
use primus_fhe_core::{SecretCoefficient, plaintext::PlaintextEmbedding};
use primus_integer::{FheUint, SignedInteger};
use primus_lwe::LweCiphertext;
use primus_reduce::RingContext;
use primus_tfhe::Ciphertext;
use rand::distr::{Distribution, Uniform};

use crate::{NtruClientKey, NtruKeyError, NtruTfheParameters};

/// Encrypts external LWE messages under the binary client NTRU coefficients.
pub struct NtruEncryptor<'a, T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters: &'a NtruTfheParameters<T, M>,
    key: &'a NtruClientKey<T>,
}

impl<'a, T, M> NtruEncryptor<'a, T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates an encryptor after checking client-key compatibility.
    pub fn new(
        parameters: &'a NtruTfheParameters<T, M>,
        key: &'a NtruClientKey<T>,
    ) -> Result<Self, NtruClientError> {
        key.check_compatible(parameters)?;
        Ok(Self { parameters, key })
    }

    /// Encrypts an unsigned message in `[0, t)`.
    pub fn encrypt<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<Ciphertext<T>, NtruClientError>
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

    /// Encrypts an unsigned message in the programmable front half `[0, t/2)`.
    pub fn encrypt_padded<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<Ciphertext<T>, NtruClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        if message >= (self.parameters.plain_modulus_value() >> 1u32) {
            return Err(NtruClientError::MessageOutsidePaddedDomain);
        }
        Ok(Ciphertext::from_lwe(self.encrypt_with_embedding(
            message,
            PlaintextEmbedding::Unsigned,
            rng,
        )))
    }

    /// Encrypts a centered modular message in `[0, t)`.
    pub fn encrypt_centered<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<Ciphertext<T>, NtruClientError>
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

    /// Produces one LWE sample using the signed coefficient view of `f_client`.
    fn encrypt_with_embedding<R>(
        &self,
        message: T,
        embedding: PlaintextEmbedding,
        rng: &mut R,
    ) -> LweCiphertext<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let parameters = self.parameters.external_lwe();
        encrypt_lwe_with_signed_secret(
            self.key.external_lwe_secret_key(),
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
    pub fn new(
        parameters: &'a NtruTfheParameters<T, M>,
        key: &'a NtruClientKey<T>,
    ) -> Result<Self, NtruClientError> {
        key.check_compatible(parameters)?;
        Ok(Self { parameters, key })
    }

    /// Decrypts to the canonical representative in `[0, t)`.
    pub fn decrypt<Msg>(&self, ciphertext: &Ciphertext<T>) -> Result<Msg, NtruClientError>
    where
        Msg: TryFrom<T>,
    {
        let expected = self.parameters.external_lwe().dimension();
        let actual = ciphertext.dimension();
        if actual != expected {
            return Err(NtruClientError::CiphertextDimensionMismatch { expected, actual });
        }
        let parameters = self.parameters.external_lwe();
        let (mask, body) = ciphertext.as_lwe().a_b();
        let modulus = parameters.cipher_modulus();
        let dot_product = modulus.reduce_dot_product_iter(
            mask.iter().copied(),
            self.key
                .external_lwe_secret_key()
                .iter()
                .copied()
                .map(|coefficient| encode_for_ring(coefficient, modulus)),
        );
        let message = parameters
            .plaintext_codec()
            .decode_value(modulus.reduce_sub(body, dot_product));
        Msg::try_from(message).map_err(|_| NtruClientError::PlaintextConversion)
    }
}

/// Encrypts an LWE sample with a canonical signed ring secret.
#[allow(clippy::too_many_arguments)]
fn encrypt_lwe_with_signed_secret<T, M, R>(
    secret_key: &[SecretCoefficient<T>],
    message: T,
    modulus: M,
    uniform: Uniform<T>,
    gaussian: &DiscreteGaussian<T>,
    codec: &primus_fhe_core::plaintext::PlaintextCodec<T>,
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

/// Encodes a signed secret coefficient in an explicit or native ring.
#[inline]
fn encode_for_ring<T, M>(coefficient: SecretCoefficient<T>, modulus: M) -> T
where
    T: FheUint,
    M: RingContext<T>,
{
    match modulus.explicit_value() {
        Some(modulus) => {
            if coefficient.is_negative() {
                debug_assert!(coefficient.unsigned_abs() < modulus);
                modulus.wrapping_add_signed(coefficient)
            } else {
                coefficient.cast_to_unsigned()
            }
        }
        None => coefficient.cast_to_unsigned(),
    }
}

/// An error produced by the NTRU TFHE client API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NtruClientError {
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
