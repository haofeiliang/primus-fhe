//! Homomorphic automorphisms with representation-specific evaluation keys.

mod fourier;
mod ntt;
pub use fourier::{FourierGlweAutomorphismKey, FourierGlweAutomorphismWorkspace};
pub use ntt::{NttGlweAutomorphismKey, NttGlweAutomorphismWorkspace};
