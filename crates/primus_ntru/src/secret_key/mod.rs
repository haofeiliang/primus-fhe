//! NTRU secret key types.

mod coeff;
mod fourier;
mod ntt;

pub use coeff::NtruSecretKey;
pub use fourier::{
    FourierNtruDecryptContext, FourierNtruEncryptContext, FourierNtruGadgetEncryptContext,
    FourierNtruSecretKey,
};
pub use ntt::{NttNtruGadgetEncryptContext, NttNtruSecretKey};
