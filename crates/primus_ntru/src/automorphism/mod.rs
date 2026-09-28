//! Homomorphic automorphisms of scalar NTRU ciphertexts.

mod fourier;
mod ntt;

pub use fourier::{FourierNtruAutomorphismKey, FourierNtruAutomorphismWorkspace};
pub use ntt::{NttNtruAutomorphismKey, NttNtruAutomorphismWorkspace};
