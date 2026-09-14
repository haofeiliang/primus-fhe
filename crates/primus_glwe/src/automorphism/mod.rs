//! Homomorphic automorphisms with representation-specific evaluation keys.

mod fourier;
mod ntt;
pub use fourier::{FourierGlweAutomorphismContext, FourierGlweAutomorphismKey};
pub use ntt::{NttGlweAutomorphismContext, NttGlweAutomorphismKey};
