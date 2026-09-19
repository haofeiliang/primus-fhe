//! Sparse keys and coefficient-aggregation blind rotation for the Fourier backend.

mod blind_rotation;
mod key;

pub use blind_rotation::SparseGlweBlindRotationContext;
pub use key::SparseGlweBootstrappingKey;
