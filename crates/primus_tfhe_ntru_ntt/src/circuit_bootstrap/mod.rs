//! Optional circuit-bootstrap parameters, keys, and evaluation.

mod control;
mod evaluator;
mod key;
mod one_hot;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;
pub use one_hot::{
    NlevSelectors, NttNgswSelectors, OneHotBootstrapError, OneHotCircuitBootstrapEvaluator,
    OneHotLookupTable, OneHotProjection,
};
/// Shared CBS parameters specialized to this backend's modulus domain.
pub type CbsParameters<T> = primus_tfhe_ntru::CbsParameters<T, primus_modulus::BarrettModulus<T>>;
