//! Boolean encryption and Fourier-backed gate evaluation.

use primus_encoding::RoundedCodec;
use primus_fft::FftTable;
use primus_fft::TorusFftValue;
use primus_lwe::LwePublicKey;
use primus_modulus::NativeModulus;
use primus_reduce::Modulus;

use crate::{
    Evaluator, ExternalLweSecretKey, ServerKey, TfheClientError, TfheContext, TfheEvaluationError,
};

pub use crate::error::BooleanError;
pub use primus_tfhe::BooleanGate;

/// Boolean encryptor for the native-torus Fourier backend.
pub type BooleanEncryptor<'a, T, Key = crate::LweSecretKeyRef<'a, T>> =
    primus_tfhe_glwe::BooleanEncryptor<'a, T, NativeModulus<T>, Key>;

/// Boolean decryptor for the native-torus Fourier backend.
pub type BooleanDecryptor<'a, T> = primus_tfhe_glwe::BooleanDecryptor<'a, T, NativeModulus<T>>;

/// Boolean gate evaluator backed by Fourier programmable bootstrapping.
///
/// See `BooleanEvaluator` in [`primus_tfhe`] for the external encoding
/// and internal LUT scale.
pub type BooleanEvaluator<'a, T, Table> =
    primus_tfhe::BooleanEvaluator<T, NativeModulus<T>, Evaluator<'a, T, Table>>;

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates a secret-key Boolean encryptor, requiring `t = 4`.
    /// Inherits [`Self::encryptor`]'s signed-secret range contract.
    pub fn boolean_encryptor<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
        codec: &'a RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<BooleanEncryptor<'a, T>, TfheClientError> {
        Ok(BooleanEncryptor::try_new(
            self.encryptor(secret_key, codec)?,
        )?)
    }

    /// Creates a public-key Boolean encryptor, requiring `t = 4`.
    /// Inherits [`Self::public_encryptor`]'s key identity and noise requirements.
    pub fn boolean_public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
        codec: &'a RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<BooleanEncryptor<'a, T, &'a LwePublicKey<T>>, BooleanError> {
        BooleanEncryptor::try_new(self.public_encryptor(public_key, codec)?)
    }

    /// Creates a Boolean decryptor after checking the external secret and `t = 4`.
    /// Inherits [`Self::decryptor`]'s signed-secret range contract.
    pub fn boolean_decryptor<'a>(
        &'a self,
        secret_key: ExternalLweSecretKey<'a, T>,
        codec: &'a RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<BooleanDecryptor<'a, T>, TfheClientError> {
        Ok(BooleanDecryptor::try_new(
            self.decryptor(secret_key, codec)?,
        )?)
    }

    /// Creates a Boolean evaluator with this context's PBS, gate LUTs and workspace.
    /// Requires `t = 4`; online `_to` operations reuse the allocated storage.
    ///
    /// Inherits [`Evaluator::try_new`]'s Fourier table identity requirement.
    pub fn boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
        codec: &RoundedCodec<T, NativeModulus<T>>,
    ) -> Result<BooleanEvaluator<'a, T, Table>, TfheEvaluationError> {
        if codec.ciphertext_modulus().explicit_value()
            != self.parameters().cipher_modulus().explicit_value()
        {
            return Err(TfheEvaluationError::LookupTable(
                crate::LookupTableError::InputModulusMismatch,
            ));
        }
        BooleanEvaluator::try_new(
            self.parameters().external_lwe_dimension(),
            self.parameters().blind_rotation_ggsw().poly_length(),
            codec,
            self.parameters().blind_rotation_ggsw().cipher_modulus(),
            self.evaluator(server_key)?,
        )
    }
}
