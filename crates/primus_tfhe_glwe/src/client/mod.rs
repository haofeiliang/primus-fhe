use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweClientParameters};

use crate::{ClientKey, TfheClientError, TfheParameters};

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M> {
    /// Binds the active external secret to a message codec at the same ciphertext modulus.
    /// A new codec reuses the same key; noise and programmable capacity remain caller requirements.
    pub fn encryptor<'a>(
        &'a self,
        key: &'a ClientKey<T>,
        codec: &'a RoundedCodec<T, M>,
    ) -> Result<Encryptor<'a, T, M>, TfheClientError> {
        key.check_compatible(self)?;
        Ok(Encryptor::try_new(
            self.client_parameters(codec)?,
            key.external_lwe_secret_key(),
        )?)
    }

    /// Checks an external public key and its message codec's ciphertext modulus.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
        codec: &'a RoundedCodec<T, M>,
    ) -> Result<Encryptor<'a, T, M, &'a LwePublicKey<T>>, ClientError> {
        Encryptor::try_new(self.client_parameters(codec)?, key)
    }

    /// Binds the active external secret and a decoder at the key's ciphertext modulus.
    /// The selected message encoding must match the input ciphertext, including LUT outputs.
    pub fn decryptor<'a>(
        &self,
        key: &'a ClientKey<T>,
        codec: &'a RoundedCodec<T, M>,
    ) -> Result<Decryptor<'a, T, M>, TfheClientError> {
        key.check_compatible(self)?;
        self.check_codec(codec)?;
        Ok(Decryptor::new(codec, key.external_lwe_secret_key()))
    }

    fn check_codec(&self, codec: &RoundedCodec<T, M>) -> Result<(), ClientError> {
        if codec.ciphertext_modulus().explicit_value() != self.cipher_modulus().explicit_value() {
            return Err(ClientError::CodecModulusMismatch);
        }
        Ok(())
    }

    // KS→BR exposes the signed kN accumulator secret and its fresh noise. BR→KS
    // exposes the small secret and its noise; neither choice depends on message t.
    fn client_parameters<'a>(
        &'a self,
        codec: &'a RoundedCodec<T, M>,
    ) -> Result<LweClientParameters<'a, T, M>, ClientError> {
        self.check_codec(codec)?;
        let noise = match self.pbs_order() {
            crate::PbsOrder::BootstrapKeyswitch => self.small_lwe().noise_distribution(),
            crate::PbsOrder::KeyswitchBootstrap => self.blind_rotation_ggsw().noise_distribution(),
        };
        LweClientParameters::try_from_parts(self.external_lwe_dimension(), codec, noise)
    }
}
