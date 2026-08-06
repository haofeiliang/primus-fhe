mod coeff;
mod external_product;
mod fourier;
mod ntt;

pub use coeff::{Ngsw, NgswIter, NgswIterMut};
pub use fourier::{FourierNgsw, FourierNgswIter, FourierNgswIterMut, FourierNgswOwned};
pub use ntt::{NttNgsw, NttNgswIter, NttNgswIterMut};

/// TFHE torus NGSW ciphertext in the coefficient domain.
pub type TorusNgsw<S> = Ngsw<S>;
