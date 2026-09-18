//! Boolean encryption and Fourier-backed gate evaluation.

use primus_modulus::NativeModulus;

use crate::Evaluator;

pub use crate::error::BooleanError;
pub use primus_tfhe::BooleanGate;

/// Boolean encryptor for the native-torus Fourier backend.
pub type BooleanEncryptor<'a, T, Key = crate::ClientKey<T>> =
    primus_tfhe_ntru::BooleanEncryptor<'a, T, NativeModulus<T>, Key>;

/// Boolean decryptor for the native-torus Fourier backend.
pub type BooleanDecryptor<'a, T> = primus_tfhe_ntru::BooleanDecryptor<'a, T, NativeModulus<T>>;

/// Boolean gate evaluator backed by Fourier programmable bootstrapping.
///
/// See `BooleanEvaluator` in [`primus_tfhe`] for the external encoding
/// and internal LUT scale.
pub type BooleanEvaluator<'a, T, Table> =
    primus_tfhe::BooleanEvaluator<T, NativeModulus<T>, Evaluator<'a, T, Table>>;
