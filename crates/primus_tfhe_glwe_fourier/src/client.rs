//! External LWE client constructors for the bound TFHE context.

use primus_encoding::RoundedCodec;
use primus_fft::FftTable;
use primus_fft::TorusFftValue;
use primus_lwe::LwePublicKey;
use primus_modulus::NativeModulus;

use crate::{
    ClientError, Decryptor, Encryptor, ExternalLweSecretKey, TfheClientError, TfheContext,
};

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates an encryptor after checking only the external secret.
    /// Inherits [`primus_tfhe_glwe::TfheParameters::encryptor`]'s signed-range contract.
    pub fn encryptor<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
        codec: &'a RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<Encryptor<'a, T>, TfheClientError> {
        self.parameters().encryptor(secret_key, codec)
    }

    /// Checks an external LWE public key and creates its encryptor.
    /// Key identity and noise requirements follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
        codec: &'a RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>>, ClientError> {
        self.parameters().public_encryptor(public_key, codec)
    }

    /// Creates a decryptor after checking only the external secret.
    /// Inherits [`primus_tfhe_glwe::TfheParameters::decryptor`]'s signed-range contract.
    pub fn decryptor<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
        codec: &'a RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<Decryptor<'a, T>, TfheClientError> {
        self.parameters().decryptor(secret_key, codec)
    }
}
