use super::{BooleanError, validate_boolean_parameters};
use crate::{ClientKey, Decryptor, EncryptionKey, Encryptor, LweCiphertext, TfheParameters};
use primus_integer::FheUint;
use primus_reduce::RingContext;

/// Encrypts Boolean values under the standard 0/1 encoding modulo 4.
/// Accepts a client secret key or LWE public key; public-key noise and identity
/// requirements follow [`EncryptionKey`].
pub struct BooleanEncryptor<'a, T, LM, GM, Key = ClientKey<T>>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    inner: Encryptor<'a, T, LM, GM, Key>,
}

impl<'a, T, LM, GM, Key> BooleanEncryptor<'a, T, LM, GM, Key>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
    Key: EncryptionKey<T, LM, GM>,
{
    /// Creates a Boolean encryptor and validates the required plaintext
    /// modulus.
    pub fn try_new(
        parameters: &'a TfheParameters<T, LM, GM>,
        key: &'a Key,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        Ok(Self {
            inner: Encryptor::try_new(parameters, key)?,
        })
    }

    /// Encrypts one Boolean value.
    pub fn encrypt<R>(&self, message: bool, rng: &mut R) -> Result<LweCiphertext<T>, BooleanError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let message = if message { T::ONE } else { T::ZERO };
        Ok(self.inner.encrypt_padded(message, rng)?)
    }

    /// Encrypts a Boolean value into existing LWE storage without allocating.
    /// Shares [`Encryptor::encrypt_to`]'s output-dimension and RNG-panic contracts.
    pub fn encrypt_to<R>(
        &self,
        message: bool,
        output: &mut LweCiphertext<T>,
        rng: &mut R,
    ) -> Result<(), BooleanError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let message = if message { T::ONE } else { T::ZERO };
        Ok(self.inner.encrypt_padded_to(message, output, rng)?)
    }
}

/// Decrypts ciphertexts using the standard 0/1 Boolean encoding.
pub struct BooleanDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    inner: Decryptor<'a, T, LM, GM>,
}

impl<'a, T, LM, GM> BooleanDecryptor<'a, T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates a Boolean decryptor and validates the required plaintext
    /// modulus.
    pub fn try_new(
        parameters: &'a TfheParameters<T, LM, GM>,
        key: &'a ClientKey<T>,
    ) -> Result<Self, BooleanError> {
        validate_boolean_parameters(parameters)?;
        Ok(Self {
            inner: Decryptor::try_new(parameters, key)?,
        })
    }

    /// Decrypts one Boolean ciphertext.
    ///
    /// Uses rounded encoding modulo 4 and rejects decoded values other than 0/1.
    /// The raw ciphertext must satisfy [`Decryptor::decrypt_phase`]'s key,
    /// modulus and canonical-coefficient requirements.
    pub fn decrypt(&self, ciphertext: &LweCiphertext<T>) -> Result<bool, BooleanError> {
        let message = self.inner.decrypt(ciphertext)?;
        if message == T::ZERO {
            Ok(false)
        } else if message == T::ONE {
            Ok(true)
        } else {
            Err(BooleanError::InvalidPlaintext)
        }
    }
}
