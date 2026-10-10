//! Sparse key generation and blind rotation for the NTT backend.

mod aggregation;
mod blind_rotation;
mod key;
pub(crate) use key::SparseKeyLayout;

pub use blind_rotation::SparseGlweBlindRotationWorkspace;
pub use primus_tfhe_glwe::SparseGlweBootstrappingKey;
