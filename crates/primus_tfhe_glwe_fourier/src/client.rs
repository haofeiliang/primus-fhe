//! External LWE client constructors for the bound TFHE context.

use primus_fft::FftTable;
use primus_fft::TorusFftValue;
use primus_lwe::LwePublicKey;

use crate::{ClientError, ClientKey, Decryptor, Encryptor, TfheClientError, TfheContext};

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates an encryptor after checking the family client key.
    pub fn encryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Encryptor<'a, T>, TfheClientError> {
        self.parameters().encryptor(client_key)
    }

    /// Checks an external LWE public key and creates its encryptor.
    /// Key identity and noise requirements follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>>, ClientError> {
        self.parameters().public_encryptor(public_key)
    }

    /// Creates a decryptor after checking the family client key.
    pub fn decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T>, TfheClientError> {
        self.parameters().decryptor(client_key)
    }
}
