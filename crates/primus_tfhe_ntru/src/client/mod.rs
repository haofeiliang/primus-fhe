use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweClientParameters};

use crate::{ClientKey, TfheClientError, TfheParameters};

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> TfheParameters<T, M, LM> {
    /// Binds the active external secret to a message codec at the same ciphertext modulus.
    /// A new codec reuses the same key; noise and programmable capacity remain caller requirements.
    pub fn encryptor<'a>(
        &'a self,
        key: &'a ClientKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, LM>, TfheClientError> {
        key.check_compatible(self)?;
        Ok(Encryptor::try_new(
            self.client_parameters(codec)?,
            key.external_lwe_secret_key().as_view(),
        )?)
    }

    /// Checks an external public key and its message codec's ciphertext modulus.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, LM, &'a LwePublicKey<T>>, ClientError> {
        Encryptor::try_new(self.client_parameters(codec)?, key)
    }

    /// Binds the active external secret and a decoder at the key's ciphertext modulus.
    /// The selected message encoding must match the input ciphertext, including LUT outputs.
    pub fn decryptor<'a>(
        &self,
        key: &'a ClientKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        key.check_compatible(self)?;
        self.check_codec(codec)?;
        Ok(Decryptor::new(
            codec,
            key.external_lwe_secret_key().as_view(),
        ))
    }

    fn check_codec(&self, codec: &RoundedCodec<T, LM>) -> Result<(), ClientError> {
        if codec.ciphertext_modulus().explicit_value()
            != self.external_lwe().cipher_modulus().explicit_value()
        {
            return Err(ClientError::CodecModulusMismatch);
        }
        Ok(())
    }

    // The external LWE secret and its fresh noise are independent of Q and message t.
    fn client_parameters<'a>(
        &'a self,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<LweClientParameters<'a, T, LM>, ClientError> {
        self.check_codec(codec)?;
        let noise = self.external_lwe().noise_distribution();
        LweClientParameters::try_from_parts(self.external_lwe_dimension(), codec, noise)
    }
}
