//! External LWE client constructors for the bound TFHE context.

use primus_encoding::{MessageDecoder, RoundedCodec};
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
    /// Binds the configured Rounded input shared by PBS, ManyLUT and factorized MVB.
    /// CBS/one-hot programs with the same input domain can use this factory.
    ///
    /// Copies the encoding state and borrows only the external secret and fresh
    /// noise sampler. No LUT or output codec is needed.
    pub fn encryptor<'a>(
        &'a self,
        secret_key: &'a LweSecretKey<T>,
    ) -> Result<Encryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.parameters().encryptor(secret_key)
    }

    /// Binds the configured Rounded input to an external LWE public key.
    /// Key identity and combined noise follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>, LM>, ClientError> {
        self.parameters().public_encryptor(public_key)
    }

    /// Binds the configured Rounded output for ordinary PBS and ManyLUT.
    ///
    /// The decoder uses the returned LWE modulus, independently of the LUT's
    /// accumulator modulus. It copies decoding state and borrows only the secret.
    /// Factorized MVB outputs require [`Self::mvb_decryptor`] instead.
    pub fn pbs_decryptor<'a>(
        &self,
        secret_key: &'a LweSecretKey<T>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().pbs_decryptor(secret_key)
    }

    /// Binds the configured Scaled output for factorized MVB.
    ///
    /// Uses the returned LWE modulus and retains its own decoding state.
    /// Codec validity does not establish the factor amplification, transform
    /// and return-stage noise budget.
    pub fn mvb_decryptor<'a>(
        &self,
        secret_key: &'a LweSecretKey<T>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().mvb_decryptor(secret_key)
    }

    // Advanced entries bind explicitly prepared codecs in the external LWE domain.

    /// Binds an explicit Rounded input codec after checking the external secret.
    pub fn encryptor_with_codec<'a>(
        &'a self,
        secret_key: &'a LweSecretKey<T>,
        codec: &RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        self.parameters().encryptor_with_codec(secret_key, codec)
    }

    /// Binds an explicit Rounded input codec to an external LWE public key.
    /// Key identity and noise requirements follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor_with_codec<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
        codec: &RoundedCodec<T, LM>,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>, LM>, ClientError> {
        self.parameters()
            .public_encryptor_with_codec(public_key, codec)
    }

    /// Binds a Rounded or Scaled output codec after checking the external
    /// secret and ciphertext modulus. Copies the prepared decoding state.
    pub fn decryptor<'a>(
        &self,
        secret_key: &'a LweSecretKey<T>,
        codec: impl Into<MessageDecoder<T, LM>>,
    ) -> Result<Decryptor<'a, T, LM>, TfheClientError> {
        self.parameters().decryptor_with_codec(secret_key, codec)
    }
}
