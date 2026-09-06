mod cmux;
mod coeff;
mod external_product;
mod fourier;
mod ntt;

pub use coeff::{Ngsw, NgswIter, NgswIterMut};
pub use fourier::{FourierNgsw, FourierNgswIter, FourierNgswIterMut, FourierNgswOwned};
pub use ntt::{NttNgsw, NttNgswIter, NttNgswIterMut};

/// TFHE torus NGSW ciphertext in the coefficient domain.
///
/// This alias does not enforce the native modulus or perform encoding;
/// callers must use native-torus arithmetic and the underlying type's layout.
pub type TorusNgsw<S> = Ngsw<S>;
