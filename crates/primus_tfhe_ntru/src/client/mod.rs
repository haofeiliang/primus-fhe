use primus_encoding::{MessageDecoder, RoundedCodec};
use primus_integer::FheUint;
use primus_lwe::{LwePublicKey, LweSecretKey};
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweClientParameters};

use crate::{PbsParameters, TfheClientError, TfheKeyError};

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> PbsParameters<T, M, LM> {
    /// Binds the active external secret to a message codec at the same ciphertext modulus.
    /// Only this external secret is checked; no other setup secret is required.
    /// A new codec reuses the same key; noise and programmable capacity remain caller requirements.
    pub fn encryptor<'a>(
        &'a self,
        key: &'a LweSecretKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, LM>, TfheClientError> {
        self.check_external_secret_key(key)?;
        Ok(Encryptor::try_new(
            self.client_parameters(codec)?,
            key.as_view(),
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
    /// Accepts a Rounded or Scaled output codec, copying its prepared decoding
    /// state. Its message modulus and recovery bound must match the ciphertext.
    pub fn decryptor<'a>(
        &self,
        key: &'a LweSecretKey<T>,
        codec: impl Into<MessageDecoder<T, LM>>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.check_external_secret_key(key)?;
        let decoder = codec.into();
        self.check_codec_modulus(decoder.ciphertext_modulus())?;
        Ok(Decryptor::new(decoder, key.as_view()))
    }

    /// Generates an LWE public key using only the external secret and its fresh noise.
    /// No accumulator secret, transform table or return-key material is required.
    ///
    /// # Correctness
    /// Public-key usage and security follow [`crate::LwePublicKey`] and
    /// [`crate::EncryptionKey`]; shape/domain checks do not prove secret identity.
    ///
    /// # Errors
    /// Rejects incompatible external dimensions, distributions, residues or modulus.
    ///
    /// # Panics
    /// Panics if public-key storage `n * (n + 1)` overflows for external dimension n.
    pub fn try_generate_public_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        key: &LweSecretKey<T>,
        rng: &mut R,
    ) -> Result<LwePublicKey<T>, TfheKeyError> {
        self.check_external_secret_key(key)?;
        Ok(LwePublicKey::generate(
            key.as_view(),
            self.external_lwe(),
            rng,
        ))
    }

    fn check_codec_modulus(&self, modulus: LM) -> Result<(), ClientError> {
        if modulus.explicit_value() != self.external_lwe().cipher_modulus().explicit_value() {
            return Err(ClientError::CodecModulusMismatch);
        }
        Ok(())
    }

    // The external LWE secret and its fresh noise are independent of Q and message t.
    fn client_parameters<'a>(
        &'a self,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<LweClientParameters<'a, T, LM>, ClientError> {
        self.check_codec_modulus(codec.ciphertext_modulus())?;
        let noise = self.external_lwe().noise_distribution();
        LweClientParameters::try_from_parts(self.external_lwe_dimension(), codec, noise)
    }
}
