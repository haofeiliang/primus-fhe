use primus_encoding::{MessageDecoder, RoundedCodec};
use primus_integer::FheUint;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweClientParameters};

use crate::{ExternalLweSecretKey, PbsParameters, TfheClientError, TfheKeyError};

impl<T: FheUint, M: RingContext<T>> PbsParameters<T, M> {
    /// Binds the active external secret to a message codec at the same ciphertext modulus.
    /// Only this external secret is checked; no other setup secret is required.
    /// A new codec reuses the same key; noise and programmable capacity remain caller requirements.
    ///
    /// # Correctness
    /// Signed GLWE coefficients inherit [`primus_lwe::LweSecretKeyRef`]'s range
    /// contract; binding checks layout and distribution, not coefficient magnitudes.
    pub fn encryptor<'a>(
        &'a self,
        key: ExternalLweSecretKey<'a, T>,
        codec: &'a RoundedCodec<T, M>,
    ) -> Result<Encryptor<'a, T, M>, TfheClientError> {
        let key = key.bind(self)?;
        Ok(Encryptor::try_new(self.client_parameters(codec)?, key)?)
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
    /// Accepts a Rounded or Scaled output codec, copying its prepared decoding
    /// state. Its message modulus and recovery bound must match the ciphertext.
    /// Inherits [`Self::encryptor`]'s signed-secret range contract.
    pub fn decryptor<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
        codec: impl Into<MessageDecoder<T, M>>,
    ) -> Result<Decryptor<'a, T, M>, TfheClientError> {
        let key = key.bind(self)?;
        let decoder = codec.into();
        self.check_codec_modulus(decoder.ciphertext_modulus())?;
        Ok(Decryptor::new(decoder, key))
    }

    /// Generates an LWE public key using only the selected external secret.
    /// Uses small-LWE noise for BR→KS, or accumulator fresh noise for KS→BR.
    /// The signed kN secret is borrowed without a coefficient copy.
    ///
    /// # Correctness
    /// The secret inherits [`primus_lwe::LweSecretKeyRef`]'s range contract.
    /// Public-key usage and security follow [`crate::LwePublicKey`] and
    /// [`crate::EncryptionKey`]; shape/domain checks do not prove secret identity.
    ///
    /// # Errors
    /// Rejects an incompatible external role, layout, distribution or LWE modulus,
    /// and small-LWE coefficients outside the binary/ternary domain.
    ///
    /// # Panics
    /// Panics if public-key storage `d * (d + 1)` overflows for external dimension d.
    pub fn try_generate_public_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        key: ExternalLweSecretKey<'_, T>,
        rng: &mut R,
    ) -> Result<LwePublicKey<T>, TfheKeyError> {
        let key = key.bind(self)?;
        Ok(match self.pbs_order() {
            crate::PbsOrder::BootstrapKeyswitch => {
                LwePublicKey::generate(key, self.small_lwe(), rng)
            }
            crate::PbsOrder::KeyswitchBootstrap => {
                let glwe = self.blind_rotation_params();
                let lwe = primus_lwe::LweEncryptionParameters::new(
                    self.external_lwe_dimension(),
                    self.cipher_modulus(),
                    glwe.secret_key_distr(),
                    glwe.noise_distribution().standard_deviation(),
                );
                LwePublicKey::generate(key, &lwe, rng)
            }
        })
    }

    fn check_codec_modulus(&self, modulus: M) -> Result<(), ClientError> {
        if modulus.explicit_value() != self.cipher_modulus().explicit_value() {
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
        self.check_codec_modulus(codec.ciphertext_modulus())?;
        let noise = match self.pbs_order() {
            crate::PbsOrder::BootstrapKeyswitch => self.small_lwe().noise_distribution(),
            crate::PbsOrder::KeyswitchBootstrap => {
                self.blind_rotation_params().noise_distribution()
            }
        };
        LweClientParameters::try_from_parts(self.external_lwe_dimension(), codec, noise)
    }
}
