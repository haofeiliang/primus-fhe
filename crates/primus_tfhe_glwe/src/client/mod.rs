use primus_integer::FheUint;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweClientParameters};

use crate::{ClientKey, TfheClientError, TfheParameters};

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M> {
    /// Validates the family key and borrows its active external LWE secret.
    pub fn encryptor<'a>(
        &'a self,
        key: &'a ClientKey<T>,
    ) -> Result<Encryptor<'a, T, M>, TfheClientError> {
        key.check_compatible(self)?;
        Ok(Encryptor::try_new(
            self.client_parameters()?,
            key.external_lwe_secret_key(),
        )?)
    }

    /// Checks the external LWE public-key dimension and modulus.
    /// Key identity and noise requirements follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, M, &'a LwePublicKey<T>>, ClientError> {
        Encryptor::try_new(self.client_parameters()?, key)
    }

    /// Validates the family key and borrows its active secret and input codec.
    pub fn decryptor<'a>(
        &'a self,
        key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T, M>, TfheClientError> {
        key.check_compatible(self)?;
        Ok(Decryptor::new(
            self.input_plaintext_codec(),
            key.external_lwe_secret_key(),
        ))
    }

    // KS→BR exposes the extracted accumulator secret. Its fresh noise must
    // remain the accumulator's sampler, even though the Rounded codec is shared.
    fn client_parameters(&self) -> Result<LweClientParameters<'_, T, M>, ClientError> {
        match self.pbs_order() {
            crate::PbsOrder::BootstrapKeyswitch => Ok(LweClientParameters::new(self.small_lwe())),
            crate::PbsOrder::KeyswitchBootstrap => {
                LweClientParameters::try_with_dimension_and_noise(
                    self.small_lwe(),
                    self.external_lwe_dimension(),
                    self.accumulator_glwe().noise_distribution(),
                )
            }
        }
    }
}
