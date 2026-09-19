//! Native-torus GLWE circuit bootstrapping and its optional key material.

mod evaluator;
mod key;

pub use evaluator::CircuitBootstrapEvaluator;
pub use key::CircuitBootstrapKey;

/// GLWE circuit-bootstrap parameters with the native torus modulus.
///
/// Native reverse trace halves integers at each stage. Its rounding, trace key
/// switching, scheme-switch decomposition and FFT precision contribute to the
/// CBS error budget; see [`CircuitBootstrapEvaluator::try_new`].
pub type CircuitBootstrapParameters<T> =
    primus_tfhe_glwe::CircuitBootstrapParameters<T, primus_modulus::NativeModulus<T>>;
