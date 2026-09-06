mod coeff;
mod extract;
mod ntt;

#[cfg(feature = "rns")]
mod crt;
#[cfg(feature = "rns")]
mod dcrt;

pub use coeff::{Rlwe, RlweIter, RlweIterMut, RlweOwned};
pub use ntt::{NttRlwe, NttRlweIter, NttRlweIterMut, NttRlweOwned};

#[cfg(feature = "rns")]
pub use crt::{CrtRlwe, CrtRlweIter, CrtRlweIterMut, CrtRlweOwned};
#[cfg(feature = "rns")]
pub use dcrt::{DcrtRlwe, DcrtRlweIter, DcrtRlweIterMut, DcrtRlweOwned};
