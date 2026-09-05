mod big_uint;

mod coeff;
mod ntt;
mod truncate;

#[cfg(feature = "rns")]
mod crt;
#[cfg(feature = "rns")]
mod dcrt;
/// Fourier-domain GLWE ciphertexts.
mod fourier;

pub use big_uint::{BigUintGlwe, BigUintGlweIter, BigUintGlweIterMut};

pub use coeff::{Glwe, GlweIter, GlweIterMut};
pub use ntt::{NttGlwe, NttGlweIter, NttGlweIterMut};
pub use truncate::TruncatedGlwe;

#[cfg(feature = "rns")]
pub use crt::{CrtGlwe, CrtGlweIter, CrtGlweIterMut};
#[cfg(feature = "rns")]
pub use dcrt::{DcrtGlwe, DcrtGlweIter, DcrtGlweIterMut};
pub use fourier::{FourierGlwe, FourierGlweIter, FourierGlweIterMut, FourierGlweOwned};

/// TFHE torus GLWE ciphertext (coefficient domain).
///
/// Layout: `|--a1--| ... |--ak--|--b--|` where each `a_i` and `b` is a
/// polynomial of degree `N-1`.
pub type TorusGlwe<S> = Glwe<S>;
