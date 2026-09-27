use primus_integer::FheUint;
use primus_lwe::LwePublicKey;
use primus_reduce::RingContext;
use primus_tfhe::{ClientError, Decryptor, Encryptor, LweClientParameters};

use crate::{ClientKey, TfheClientError, TfheParameters};

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> TfheParameters<T, M, LM> {
    /// Validates the family key and borrows its external LWE secret.
    pub fn encryptor<'a>(
        &'a self,
        key: &'a ClientKey<T>,
    ) -> Result<Encryptor<'a, T, LM>, TfheClientError> {
        key.check_compatible(self)?;
        Ok(Encryptor::try_new(
            self.client_parameters(),
            key.external_lwe_secret_key().as_view(),
        )?)
    }

    /// Checks the external LWE public-key dimension and modulus.
    /// Key identity and noise requirements follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, LM, &'a LwePublicKey<T>>, ClientError> {
        Encryptor::try_new(self.client_parameters(), key)
    }

    /// Validates the family key and borrows its external secret and input codec.
    pub fn decryptor<'a>(
        &'a self,
        key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        key.check_compatible(self)?;
        Ok(Decryptor::new(
            self.input_plaintext_codec(),
            key.external_lwe_secret_key().as_view(),
        ))
    }

    fn client_parameters(&self) -> LweClientParameters<'_, T, LM> {
        LweClientParameters {
            dimension: self.external_lwe_dimension(),
            codec: self.input_plaintext_codec(),
            uniform: self.external_lwe().cipher_modulus_uniform_distr(),
            noise: self.external_lwe().noise_distribution(),
        }
    }
}
