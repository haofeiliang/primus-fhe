//! Optional circuit-bootstrap parameters, keys, and evaluation.

mod evaluator;
mod key;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;

/// GLWE circuit-bootstrap parameters with a Barrett ciphertext modulus.
///
/// Matching parameters do not establish secret or NTT representation identity;
/// see [`CircuitBootstrapEvaluator::try_new`].
pub type CircuitBootstrapParameters<T> =
    primus_tfhe_glwe::CircuitBootstrapParameters<T, primus_modulus::BarrettModulus<T>>;
