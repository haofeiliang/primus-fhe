//! External LWE client constructors for the bound TFHE context.

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;

use crate::{
    ClientError, ClientKey, Decryptor, Encryptor, LwePublicKey, TfheClientError, TfheContext,
};

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates an encryptor after checking the family client key.
    pub fn encryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.parameters().encryptor(client_key, codec)
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

    /// Creates a decryptor after checking the family client key.
    pub fn decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().decryptor(client_key, codec)
    }
}
