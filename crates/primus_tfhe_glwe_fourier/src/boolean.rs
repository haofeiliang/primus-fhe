//! Boolean encryption and Fourier-backed gate evaluation.

use primus_modulus::NativeModulus;

use crate::Evaluator;

pub use crate::error::BooleanError;
pub use primus_fhe_core::tfhe::{BooleanCiphertext, BooleanGate};

/// Boolean encryptor for the native-torus Fourier backend.
pub type BooleanEncryptor<'a, T> =
    primus_fhe_core::tfhe::BooleanEncryptor<'a, T, NativeModulus<T>, NativeModulus<T>>;

/// Boolean decryptor for the native-torus Fourier backend.
pub type BooleanDecryptor<'a, T> =
    primus_fhe_core::tfhe::BooleanDecryptor<'a, T, NativeModulus<T>, NativeModulus<T>>;

/// Boolean gate evaluator backed by Fourier programmable bootstrapping.
pub type BooleanEvaluator<'a, T, Table> = primus_fhe_core::tfhe::BooleanEvaluator<
    'a,
    T,
    NativeModulus<T>,
    NativeModulus<T>,
    Evaluator<'a, T, Table>,
>;
