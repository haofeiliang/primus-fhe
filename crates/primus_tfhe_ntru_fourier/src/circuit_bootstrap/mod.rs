//! Optional circuit-bootstrap parameters, keys, and evaluation.

mod control;
mod evaluator;
mod key;
mod one_hot;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;
pub use one_hot::{
    FourierNgswSelectors, NlevSelectors, OneHotBootstrapError, OneHotCircuitBootstrapEvaluator,
    OneHotLookupTable, OneHotProjection,
};
/// Shared CBS parameters specialized to this backend's modulus domain.
pub type CircuitBootstrapParameters<T> =
    primus_tfhe_ntru::CircuitBootstrapParameters<T, primus_modulus::NativeModulus<T>>;
