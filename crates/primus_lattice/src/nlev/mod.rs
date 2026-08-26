mod coeff;
mod external_product;
mod fourier;
mod ntt;

pub(crate) use external_product::{
    fourier_gadget_product_add_assign, fourier_gadget_product_to_accumulator,
    ntt_gadget_product_add_assign, ntt_gadget_product_to_accumulator,
};

pub use coeff::{Nlev, NlevIter, NlevIterMut};
pub use fourier::{FourierNlev, FourierNlevIter, FourierNlevIterMut, FourierNlevOwned};
pub use ntt::{NttNlev, NttNlevIter, NttNlevIterMut};

/// TFHE torus NLev ciphertext in the coefficient domain.
pub type TorusNlev<S> = Nlev<S>;
