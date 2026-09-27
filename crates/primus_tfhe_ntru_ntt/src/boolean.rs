//! Boolean encryption and NTT-backed gate evaluation.

use primus_modulus::BarrettModulus;

use crate::Evaluator;

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
