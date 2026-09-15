use super::{BooleanCiphertext, BooleanError, validate_boolean_parameters};
use crate::{GlweClientKey, GlweDecryptor, GlweEncryptionKey, GlweEncryptor, GlweTfheParameters};
use primus_integer::FheUint;
use primus_reduce::RingContext;

/// Encrypts Boolean values under the standard 0/1 encoding modulo 4.
/// Accepts a client secret key or LWE public key; public-key noise and identity
/// requirements follow [`GlweEncryptionKey`].
pub struct BooleanEncryptor<'a, T, LM, GM, Key = GlweClientKey<T>>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    inner: GlweEncryptor<'a, T, LM, GM, Key>,
}

impl<'a, T, LM, GM, Key> BooleanEncryptor<'a, T, LM, GM, Key>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
    Key: GlweEncryptionKey<T, LM, GM>,
{
    /// Creates a Boolean encryptor and validates the required plaintext
    /// modulus.
    pub fn new(
        parameters: &'a GlweTfheParameters<T, LM, GM>,
        key: &'a Key,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        Ok(Self {
            inner: GlweEncryptor::try_new(parameters, key)?,
        })
    }

    /// Encrypts one Boolean value.
    pub fn encrypt<R>(
        &self,
        message: bool,
        rng: &mut R,
    ) -> Result<BooleanCiphertext<T>, BooleanError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let message = if message { T::ONE } else { T::ZERO };
        Ok(BooleanCiphertext::from_raw(
            self.inner.encrypt_padded(message, rng)?,
        ))
    }
}

/// Decrypts ciphertexts using the standard 0/1 Boolean encoding.
pub struct BooleanDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    inner: GlweDecryptor<'a, T, LM, GM>,
}

impl<'a, T, LM, GM> BooleanDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates a Boolean decryptor and validates the required plaintext
    /// modulus.
    pub fn new(
        parameters: &'a GlweTfheParameters<T, LM, GM>,
        key: &'a GlweClientKey<T>,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        Ok(Self {
            inner: GlweDecryptor::try_new(parameters, key)?,
        })
    }

    /// Decrypts one Boolean ciphertext.
    pub fn decrypt(&self, ciphertext: &BooleanCiphertext<T>) -> Result<bool, BooleanError> {
        let message = self.inner.decrypt::<T>(ciphertext.as_raw())?;
        if message == T::ZERO {
            Ok(false)
        } else if message == T::ONE {
            Ok(true)
        } else {
            Err(BooleanError::InvalidPlaintext)
        }
    }
}
