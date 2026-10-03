//! External LWE client constructors for the bound TFHE context.

use primus_encoding::RoundedCodec;
use primus_fft::FftTable;
use primus_fft::TorusFftValue;
use primus_lwe::LweSecretKey;

use crate::{ClientError, Decryptor, Encryptor, LwePublicKey, TfheClientError, TfheContext};

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates an encryptor after checking only the external secret.
    pub fn encryptor<'a>(
        &'a self,
        secret_key: &'a LweSecretKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.parameters().encryptor(secret_key, codec)
    }

    /// Checks an external LWE public key and creates its encryptor.
    /// Key identity and noise requirements follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>, LM>, ClientError> {
        self.parameters().public_encryptor(public_key, codec)
    }

    /// Creates a decryptor after checking only the external secret.
    pub fn decryptor<'a>(
        &'a self,
        secret_key: &'a LweSecretKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().decryptor(secret_key, codec)
    }
}
