//! Boolean encryption and NTT-backed gate evaluation.

use primus_modulus::BarrettModulus;

use crate::Evaluator;

pub use crate::error::BooleanError;
pub use primus_tfhe_glwe::BooleanGate;

/// Boolean encryptor for the explicit-modulus NTT backend.
pub type BooleanEncryptor<'a, T, Key = crate::ClientKey<T>> =
    primus_tfhe_glwe::BooleanEncryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>, Key>;

/// Boolean decryptor for the explicit-modulus NTT backend.
pub type BooleanDecryptor<'a, T> =
    primus_tfhe_glwe::BooleanDecryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>>;

/// Boolean gate evaluator backed by NTT programmable bootstrapping.
///
/// See `BooleanEvaluator` in [`primus_tfhe_glwe`] for the external encoding
/// and internal LUT scale.
pub type BooleanEvaluator<'a, T, Table> =
    primus_tfhe_glwe::BooleanEvaluator<T, BarrettModulus<T>, Evaluator<'a, T, Table>>;
