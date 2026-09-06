mod coeff;
mod external_product;
mod fourier;
mod ntt;

pub use coeff::{Nlev, NlevIter, NlevIterMut};
pub use fourier::{FourierNlev, FourierNlevIter, FourierNlevIterMut, FourierNlevOwned};
pub use ntt::{NttNlev, NttNlevIter, NttNlevIterMut};

/// TFHE torus NLev ciphertext in the coefficient domain.
pub type TorusNlev<S> = Nlev<S>;
