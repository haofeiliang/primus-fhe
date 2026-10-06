//! Sparse keys and coefficient-aggregation blind rotation for the Fourier backend.

mod blind_rotation;
mod key;

use crate::SparseGlweBootstrappingKey;
pub use blind_rotation::SparseGlweBlindRotationWorkspace;
