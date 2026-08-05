//! Boolean encryption and Fourier-backed gate evaluation.

use primus_modulus::NativeModulus;

use crate::Evaluator;

pub use crate::error::BooleanError;
pub use primus_tfhe::{BooleanCiphertext, BooleanGate};

/// Boolean encryptor for the native-torus Fourier backend.
pub type BooleanEncryptor<'a, T> =
    primus_tfhe::BooleanEncryptor<'a, T, NativeModulus<T>, NativeModulus<T>>;

/// Boolean decryptor for the native-torus Fourier backend.
pub type BooleanDecryptor<'a, T> =
    primus_tfhe::BooleanDecryptor<'a, T, NativeModulus<T>, NativeModulus<T>>;

/// Boolean gate evaluator backed by Fourier programmable bootstrapping.
pub type BooleanEvaluator<'a, T, Table> = primus_tfhe::BooleanEvaluator<
    'a,
    T,
    NativeModulus<T>,
    NativeModulus<T>,
    Evaluator<'a, T, Table>,
>;
