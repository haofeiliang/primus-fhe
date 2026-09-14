//! Homomorphic automorphisms of scalar NTRU ciphertexts.

mod fourier;
mod ntt;

pub use fourier::{FourierNtruAutomorphismContext, FourierNtruAutomorphismKey};
pub use ntt::{NttNtruAutomorphismContext, NttNtruAutomorphismKey};
