mod coeff;
mod ntt;

#[cfg(feature = "rns")]
mod crt;
#[cfg(feature = "rns")]
mod dcrt;
#[cfg(feature = "rns")]
mod external_product;
/// Fourier-domain GLev ciphertexts.
mod fourier;

pub use coeff::{Glev, GlevIter, GlevIterMut};
pub use ntt::{NttGlev, NttGlevIter, NttGlevIterMut};

#[cfg(feature = "rns")]
pub use crt::{CrtGlev, CrtGlevIter, CrtGlevIterMut};
#[cfg(feature = "rns")]
pub use dcrt::{DcrtGlev, DcrtGlevIter, DcrtGlevIterMut};
pub use fourier::{FourierGlev, FourierGlevIter, FourierGlevIterMut, FourierGlevOwned};

/// TFHE torus GLev ciphertext (coefficient domain).
///
/// List of [`TorusGlwe`](crate::glwe::TorusGlwe) per gadget decomposition level.
///
/// This alias does not enforce the native modulus or perform encoding;
/// callers must use native-torus arithmetic and the underlying type's layout.
pub type TorusGlev<S> = Glev<S>;
