mod coeff;
mod ntt;

mod crt;
mod dcrt;
/// Fourier-domain GLev ciphertexts.
mod fourier;

pub use coeff::{Glev, GlevIter, GlevIterMut};
pub use ntt::{NttGlev, NttGlevIter, NttGlevIterMut};

pub use crt::{CrtGlev, CrtGlevIter, CrtGlevIterMut};
pub use dcrt::{DcrtGlev, DcrtGlevIter, DcrtGlevIterMut};
pub use fourier::{FourierGlev, FourierGlevIter, FourierGlevIterMut, FourierGlevOwned};

/// TFHE torus GLev ciphertext (coefficient domain).
///
/// List of [`TorusGlwe`](crate::glwe::TorusGlwe) per gadget decomposition level.
pub type TorusGlev<S> = Glev<S>;
