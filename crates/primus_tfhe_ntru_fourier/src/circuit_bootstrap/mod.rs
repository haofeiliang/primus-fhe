//! Optional circuit-bootstrap parameters, keys, and evaluation.

mod evaluator;
mod key;
mod one_hot;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;
pub use one_hot::{OneHotBootstrapError, OneHotCircuitBootstrapEvaluator, OneHotLookupTable};
/// Shared CBS parameters specialized to this backend's modulus domain.
pub type CircuitBootstrapParameters<T> =
    primus_tfhe_ntru::CircuitBootstrapParameters<T, primus_modulus::NativeModulus<T>>;
