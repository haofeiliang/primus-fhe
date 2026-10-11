use primus_encoding::{MessageDecoder, RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweClientParameters};

use crate::{ExternalLweSecretKey, PbsParameters, TfheClientError, TfheKeyError};

impl<T: FheUint, M: RingContext<T>> PbsParameters<T, M> {
    /// Binds the configured Rounded input shared by PBS, ManyLUT and factorized MVB.
    /// Copies the encoding state and borrows the active external secret and fresh
    /// noise sampler. No LUT or output codec is needed.
    ///
    /// # Correctness
    /// Inherits [`Self::encryptor_with_codec`]'s signed-secret range contract.
    pub fn encryptor<'a>(
        &'a self,
        key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Encryptor<'a, T, M>, TfheClientError> {
        let codec = RoundedCodec::try_new(self.messages().input_modulus, self.cipher_modulus())
            .map_err(ClientError::from)?;
        self.encryptor_with_codec(key, &codec)
    }

    /// Binds the configured Rounded input to an external LWE public key.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, M, &'a LwePublicKey<T>>, ClientError> {
        let codec = RoundedCodec::try_new(self.messages().input_modulus, self.cipher_modulus())?;
        self.public_encryptor_with_codec(key, &codec)
    }

    /// Binds the configured Rounded output for ordinary PBS and ManyLUT.
    /// Copies decoding state and borrows only the external secret. Factorized
    /// MVB outputs require [`Self::mvb_decryptor`] instead.
    ///
    /// # Correctness
    /// Inherits [`Self::decryptor_with_codec`]'s secret and recovery contracts.
    pub fn pbs_decryptor<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Decryptor<'a, T, M>, TfheClientError> {
        let codec = RoundedCodec::try_new(self.messages().output_modulus, self.cipher_modulus())
            .map_err(ClientError::from)?;
        self.decryptor_with_codec(key, &codec)
    }

    /// Binds the configured Scaled output for factorized MVB.
    /// Copies decoding state and borrows only the external secret. Codec validity
    /// does not establish the factor amplification, transform or return noise budget.
    ///
    /// # Correctness
    /// Inherits [`Self::decryptor_with_codec`]'s secret and recovery contracts.
    pub fn mvb_decryptor<'a>(
        &self,
        key: ExternalLweSecretKey<'a, T>,
    ) -> Result<Decryptor<'a, T, M>, TfheClientError> {
        let codec = ScaledCodec::try_new(self.messages().output_modulus, self.cipher_modulus())
            .map_err(ClientError::from)?;
        self.decryptor_with_codec(key, &codec)
    }

    /// Binds the active external secret to a message codec at the same ciphertext modulus.
    /// Only this external secret is checked; no other setup secret is required.
    /// Copies the codec, so it need not outlive the client. A new codec reuses
    /// the same key; noise and programmable capacity remain caller requirements.
    ///
    /// # Correctness
    /// Signed GLWE coefficients inherit [`primus_lwe::LweSecretKeyRef`]'s range
    /// contract; binding checks layout and distribution, not coefficient magnitudes.
    pub fn encryptor_with_codec<'a>(
        &'a self,
        key: ExternalLweSecretKey<'a, T>,
        codec: &RoundedCodec<T, M>,
    ) -> Result<Encryptor<'a, T, M>, TfheClientError> {
        let key = key.bind(self)?;
        Ok(Encryptor::try_new(self.client_parameters(codec)?, key)?)
    }

    /// Checks an external public key and its message codec's ciphertext modulus.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor_with_codec<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
        codec: &RoundedCodec<T, M>,
    ) -> Result<Encryptor<'a, T, M, &'a LwePublicKey<T>>, ClientError> {
        Encryptor::try_new(self.client_parameters(codec)?, key)
    }

    /// Binds the active external secret and a decoder at the key's ciphertext modulus.
    /// Accepts a Rounded or Scaled output codec, copying its prepared decoding
    /// state.
    ///
    /// # Correctness
    /// Its message modulus and recovery bound must match the ciphertext.
    /// Inherits [`Self::encryptor_with_codec`]'s signed-secret range contract.
    pub fn decryptor_with_codec<'a>(
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
                let lwe = self.small_lwe();
                LwePublicKey::generate(
                    key,
                    lwe.dimension(),
                    lwe.cipher_modulus(),
                    lwe.cipher_modulus_uniform_distr(),
                    lwe.noise_distribution(),
                    rng,
                )
            }
            crate::PbsOrder::KeyswitchBootstrap => {
                let glwe = self.blind_rotation_params().encryption_parameters();
                LwePublicKey::generate(
                    key,
                    self.external_lwe_dimension(),
                    glwe.cipher_modulus(),
                    glwe.cipher_modulus_uniform_distr(),
                    glwe.noise_distribution(),
                    rng,
                )
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
        codec: &RoundedCodec<T, M>,
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
