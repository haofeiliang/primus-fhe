mod coeff;
mod ntt;

mod crt;
mod dcrt;
/// Fourier-domain GGSW ciphertexts.
mod fourier;

pub use coeff::{Ggsw, GgswIter, GgswIterMut};
pub use ntt::{NttGgsw, NttGgswIter, NttGgswIterMut};

pub use crt::{CrtGgsw, CrtGgswIter, CrtGgswIterMut};
pub use dcrt::{DcrtGgsw, DcrtGgswIter, DcrtGgswIterMut};
pub use fourier::{FourierGgsw, FourierGgswIter, FourierGgswIterMut, FourierGgswOwned};

/// TFHE torus GGSW ciphertext (coefficient domain).
///
/// Matrix of [`TorusGlev`](crate::glev::TorusGlev) ciphertexts, one per row
/// (i.e. one per GLWE mask component plus one for the body).
pub type TorusGgsw<S> = Ggsw<S>;
