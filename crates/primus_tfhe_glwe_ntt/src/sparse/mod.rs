//! Sparse bootstrapping keys and reference blind rotation for the NTT backend.

mod blind_rotation;
mod key;

pub use blind_rotation::SparseGlweBlindRotationContext;
pub use key::SparseGlweBootstrappingKey;
