//! Coefficient-domain sparse bootstrapping keys for the NTT backend.

mod key;
mod pbc;

pub use key::{SparseBootstrappingKeyError, SparseGlweBootstrappingKey};
