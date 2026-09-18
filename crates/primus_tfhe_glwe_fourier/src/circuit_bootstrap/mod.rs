//! Optional key material for native-torus GLWE circuit bootstrapping.

mod key;
mod parameters;

pub use key::{CircuitBootstrapKey, CircuitBootstrapKeyError};
pub use parameters::{CircuitBootstrapParameterError, CircuitBootstrapParameters};
