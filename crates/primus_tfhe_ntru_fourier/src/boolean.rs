//! Boolean encryption and Fourier-backed gate evaluation.

use primus_modulus::NativeModulus;

use crate::Evaluator;

pub use crate::error::BooleanError;
pub use primus_tfhe::BooleanGate;

/// Boolean encryptor for the native-torus Fourier backend.
pub type BooleanEncryptor<'a, T, Key = crate::LweSecretKeyRef<'a, T>, LM = NativeModulus<T>> =
    primus_tfhe_ntru::BooleanEncryptor<'a, T, LM, Key>;

/// Boolean decryptor for the native-torus Fourier backend.
pub type BooleanDecryptor<'a, T, LM = NativeModulus<T>> =
    primus_tfhe_ntru::BooleanDecryptor<'a, T, LM>;

/// Boolean gate evaluator backed by Fourier programmable bootstrapping.
///
/// See `BooleanEvaluator` in [`primus_tfhe`] for the external encoding
/// and internal LUT scale.
pub type BooleanEvaluator<'a, T, Table, LM = NativeModulus<T>> =
    primus_tfhe::BooleanEvaluator<T, LM, Evaluator<'a, T, Table, LM>>;
