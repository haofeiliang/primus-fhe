//! Boolean encryption and Fourier-backed gate evaluation.

use primus_fft::FftTable;
use primus_fft::TorusFftValue;
use primus_lwe::LwePublicKey;
use primus_modulus::NativeModulus;

use crate::{ClientKey, Evaluator, ServerKey, TfheClientError, TfheContext, TfheEvaluationError};

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
    pub fn boolean_encryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<BooleanEncryptor<'a, T>, TfheClientError> {
        Ok(BooleanEncryptor::try_new(self.encryptor(client_key)?)?)
    }

    /// Creates a public-key Boolean encryptor, requiring `t = 4`.
    /// Inherits [`Self::public_encryptor`]'s key identity and noise requirements.
    pub fn boolean_public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<BooleanEncryptor<'a, T, &'a LwePublicKey<T>>, BooleanError> {
        BooleanEncryptor::try_new(self.public_encryptor(public_key)?)
    }

    /// Creates a Boolean decryptor after checking the client key and `t = 4`.
    pub fn boolean_decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<BooleanDecryptor<'a, T>, TfheClientError> {
        Ok(BooleanDecryptor::try_new(self.decryptor(client_key)?)?)
    }

    /// Creates a Boolean evaluator with this context's PBS, gate LUTs and workspace.
    /// Requires `t = 4`; online `_to` operations reuse the allocated storage.
    ///
    /// Inherits [`Evaluator::try_new`]'s Fourier table identity requirement.
    pub fn boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BooleanEvaluator<'a, T, Table>, TfheEvaluationError> {
        BooleanEvaluator::try_new(
            self.parameters().external_lwe_dimension(),
            self.parameters().accumulator_glwe().poly_length(),
            self.parameters().input_plaintext_codec(),
            self.parameters().accumulator_glwe().cipher_modulus(),
            self.evaluator(server_key)?,
        )
    }
}
