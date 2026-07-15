use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{ClientKey, LweCiphertext, LweParameters, TfheKeyError, TfheParameters};

/// A raw small-LWE ciphertext used by GLWE-based TFHE.
///
/// Encoding and higher-level state belong to wrappers such as boolean or
/// short-integer ciphertexts rather than to this raw container.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ciphertext<T: FheUint>(LweCiphertext<T>);

impl<T: FheUint> Ciphertext<T> {
    #[inline]
    fn from_lwe(ciphertext: LweCiphertext<T>) -> Self {
        Self(ciphertext)
    }

    /// Creates a ciphertext from an LWE sample after checking its dimension.
    pub fn try_from_lwe(
        ciphertext: LweCiphertext<T>,
        expected_dimension: usize,
    ) -> Result<Self, TfheClientError> {
        let expected = expected_dimension
            .checked_add(1)
            .ok_or(TfheClientError::CiphertextDimensionTooLarge)?;
        let actual = ciphertext.0.len();
        if actual != expected {
            return Err(TfheClientError::CiphertextLengthMismatch { expected, actual });
        }
        Ok(Self(ciphertext))
    }

    /// Returns the underlying LWE ciphertext.
    #[inline]
    pub fn as_lwe(&self) -> &LweCiphertext<T> {
        &self.0
    }

    /// Returns the underlying mutable LWE ciphertext.
    #[inline]
    pub fn as_lwe_mut(&mut self) -> &mut LweCiphertext<T> {
        &mut self.0
    }

    /// Decomposes this wrapper into its underlying LWE ciphertext.
    #[inline]
    pub fn into_lwe(self) -> LweCiphertext<T> {
        self.0
    }

    /// Returns the LWE dimension of this ciphertext.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.0.dimension()
    }
}

/// Encrypts raw TFHE messages with a particular encryption key.
///
/// The modulus parameter is part of the type, but FFT/NTT tables are not:
/// client-side LWE encryption does not use a transform backend.
pub struct Encryptor<'a, T, M, Key>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters: &'a LweParameters<T, M>,
    key: &'a Key,
}

impl<'a, T, M> Encryptor<'a, T, M, ClientKey<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a secret-key encryptor after checking key compatibility.
    pub fn with_client_key<GM>(
        parameters: &'a TfheParameters<T, M, GM>,
        key: &'a ClientKey<T>,
    ) -> Result<Self, TfheClientError>
    where
        GM: RingContext<T>,
    {
        key.check_compatible(parameters)?;
        Ok(Self {
            parameters: parameters.small_lwe(),
            key,
        })
    }

    /// Encrypts an unsigned message in the range `[0, t)`.
    pub fn encrypt<R, Msg>(
        &self,
        message: Msg,
        rng: &mut R,
    ) -> Result<Ciphertext<T>, TfheClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        Ok(Ciphertext::from_lwe(self.key.lwe_secret_key().encrypt(
            message,
            self.parameters,
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
    ) -> Result<Ciphertext<T>, TfheClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        let modulus = self.parameters.plain_modulus_value();
        let front_domain_len = modulus >> 1u32;
        if message >= front_domain_len {
            return Err(TfheClientError::MessageOutsidePaddedDomain);
        }
        Ok(Ciphertext::from_lwe(self.key.lwe_secret_key().encrypt(
            message,
            self.parameters,
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
    ) -> Result<Ciphertext<T>, TfheClientError>
    where
        R: rand::Rng + rand::CryptoRng,
        Msg: TryInto<T>,
    {
        let message = self.checked_message(message)?;
        Ok(Ciphertext::from_lwe(
            self.key
                .lwe_secret_key()
                .encrypt_centered(message, self.parameters, rng),
        ))
    }

    #[inline]
    fn checked_message<Msg>(&self, message: Msg) -> Result<T, TfheClientError>
    where
        Msg: TryInto<T>,
    {
        let message = message
            .try_into()
            .map_err(|_| TfheClientError::MessageConversion)?;
        if message >= self.parameters.plain_modulus_value() {
            return Err(TfheClientError::MessageOutOfRange);
        }
        Ok(message)
    }
}

/// Decrypts raw TFHE ciphertexts with the client key.
pub struct Decryptor<'a, T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters: &'a LweParameters<T, M>,
    key: &'a ClientKey<T>,
}

impl<'a, T, M> Decryptor<'a, T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a decryptor after checking key compatibility.
    pub fn new<GM>(
        parameters: &'a TfheParameters<T, M, GM>,
        key: &'a ClientKey<T>,
    ) -> Result<Self, TfheClientError>
    where
        GM: RingContext<T>,
    {
        key.check_compatible(parameters)?;
        Ok(Self {
            parameters: parameters.small_lwe(),
            key,
        })
    }

    /// Decrypts to the canonical representative in `[0, t)`.
    pub fn decrypt<Msg>(&self, ciphertext: &Ciphertext<T>) -> Result<Msg, TfheClientError>
    where
        Msg: TryFrom<T>,
    {
        let expected = self.parameters.dimension();
        let actual = ciphertext.dimension();
        if actual != expected {
            return Err(TfheClientError::CiphertextDimensionMismatch { expected, actual });
        }

        let message: T = self
            .key
            .lwe_secret_key()
            .decrypt(ciphertext.as_lwe(), self.parameters);
        Msg::try_from(message).map_err(|_| TfheClientError::PlaintextConversion)
    }
}

/// An error produced by the raw TFHE client API.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheClientError {
    /// The client key does not match the parameter set.
    #[error(transparent)]
    IncompatibleKey(#[from] TfheKeyError),

    /// The input message cannot be represented by the ciphertext integer type.
    #[error("message cannot be represented by the ciphertext integer type")]
    MessageConversion,

    /// The input message is outside the plaintext domain `[0, t)`.
    #[error("message is outside the plaintext domain")]
    MessageOutOfRange,

    /// The input message sets the padding half of the plaintext domain.
    #[error("message is outside the padded plaintext domain")]
    MessageOutsidePaddedDomain,

    /// The requested LWE dimension cannot be represented as a ciphertext
    /// coefficient count.
    #[error("LWE ciphertext dimension is too large")]
    CiphertextDimensionTooLarge,

    /// An imported LWE ciphertext has the wrong coefficient count.
    #[error("LWE ciphertext length mismatch: expected {expected}, got {actual}")]
    CiphertextLengthMismatch {
        /// Required coefficient count, including the body.
        expected: usize,
        /// Actual coefficient count.
        actual: usize,
    },

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
