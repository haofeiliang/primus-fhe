//! Boolean encryption and NTT-backed gate evaluation.

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lwe::LweSecretKey;
use primus_modulus::BarrettModulus;
use primus_ntt::MonomialNttTable;

use crate::{
    Evaluator, LwePublicKey, ServerKey, TfheClientError, TfheContext, TfheEvaluationError,
};

pub use crate::error::BooleanError;
pub use primus_tfhe::BooleanGate;

/// Boolean encryptor for the explicit-modulus NTT backend.
pub type BooleanEncryptor<'a, T, Key = crate::LweSecretKeyRef<'a, T>, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::BooleanEncryptor<'a, T, LM, Key>;

/// Boolean decryptor for the explicit-modulus NTT backend.
pub type BooleanDecryptor<'a, T, LM = BarrettModulus<T>> =
    primus_tfhe_ntru::BooleanDecryptor<'a, T, LM>;

/// Boolean gate evaluator backed by NTT programmable bootstrapping.
///
/// See `BooleanEvaluator` in [`primus_tfhe`] for the external encoding
/// and internal LUT scale.
pub type BooleanEvaluator<'a, T, Table, LM = BarrettModulus<T>> =
    primus_tfhe::BooleanEvaluator<T, LM, Evaluator<'a, T, Table, LM>>;

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates a secret-key Boolean encryptor, requiring `t = 4`.
    pub fn boolean_encryptor<'a>(
        &'a self,
        secret_key: &'a LweSecretKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<BooleanEncryptor<'a, T, crate::LweSecretKeyRef<'a, T>, LM>, TfheClientError> {
        Ok(BooleanEncryptor::try_new(
            self.encryptor_with_codec(secret_key, codec)?,
        )?)
    }

    /// Creates a public-key Boolean encryptor, requiring `t = 4`.
    /// Inherits [`Self::public_encryptor`]'s key identity and noise requirements.
    pub fn boolean_public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<BooleanEncryptor<'a, T, &'a LwePublicKey<T>, LM>, BooleanError> {
        BooleanEncryptor::try_new(self.public_encryptor_with_codec(public_key, codec)?)
    }

    /// Creates a Boolean decryptor after checking the external secret and `t = 4`.
    pub fn boolean_decryptor<'a>(
        &'a self,
        secret_key: &'a LweSecretKey<T>,
        codec: &'a RoundedCodec<T, LM>,
    ) -> Result<BooleanDecryptor<'a, T, LM>, TfheClientError> {
        Ok(BooleanDecryptor::try_new(
            self.decryptor(secret_key, codec)?,
        )?)
    }

    /// Creates a Boolean evaluator with this context's PBS, gate LUTs and workspace.
    /// Requires `t = 4`; online `_to` operations reuse the allocated storage.
    pub fn boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
        codec: &RoundedCodec<T, LM>,
    ) -> Result<BooleanEvaluator<'a, T, Table, LM>, TfheEvaluationError> {
        if codec.ciphertext_modulus().explicit_value()
            != self.parameters().external_lwe().cipher_modulus_value()
        {
            return Err(TfheEvaluationError::LookupTable(
                crate::LookupTableError::InputModulusMismatch,
            ));
        }
        BooleanEvaluator::try_new(
            self.parameters().external_lwe_dimension(),
            self.parameters().accumulator_ntru().poly_length(),
            codec,
            self.parameters().accumulator_ntru().cipher_modulus(),
            self.evaluator(server_key)?,
        )
    }
}
