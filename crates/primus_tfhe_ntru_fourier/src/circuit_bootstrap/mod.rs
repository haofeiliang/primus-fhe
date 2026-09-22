//! Optional circuit-bootstrap parameters, keys, and evaluation.

mod evaluator;
mod key;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;
/// Shared CBS parameters specialized to this backend's modulus domain.
pub type CircuitBootstrapParameters<T> =
    primus_tfhe_ntru::CircuitBootstrapParameters<T, primus_modulus::NativeModulus<T>>;
