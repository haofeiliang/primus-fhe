//! Boolean encryption and NTT-backed gate evaluation.

use primus_modulus::BarrettModulus;

use crate::Evaluator;

pub use crate::error::BooleanError;
pub use primus_fhe_core::{BooleanCiphertext, BooleanGate};

/// Boolean encryptor for the explicit-modulus NTT backend.
pub type BooleanEncryptor<'a, T> = primus_fhe_core::BooleanEncryptor<'a, T, BarrettModulus<T>>;

/// Boolean decryptor for the explicit-modulus NTT backend.
pub type BooleanDecryptor<'a, T> = primus_fhe_core::BooleanDecryptor<'a, T, BarrettModulus<T>>;

/// Boolean gate evaluator backed by NTT programmable bootstrapping.
pub type BooleanEvaluator<'a, T, Table> = primus_fhe_core::BooleanEvaluator<
    'a,
    T,
    BarrettModulus<T>,
    BarrettModulus<T>,
    Evaluator<'a, T, Table>,
>;
