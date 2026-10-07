//! Sparse key generation and blind rotation for the NTT backend.

mod aggregation;
mod blind_rotation;
mod key;
pub(crate) use key::SparseKeyLayout;

use crate::SparseGlweBootstrappingKey;
pub use blind_rotation::SparseGlweBlindRotationWorkspace;
