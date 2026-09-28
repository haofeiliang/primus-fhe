//! NTRU secret key types.

mod coeff;
mod fourier;
mod ntt;

pub use coeff::NtruSecretKey;
pub use fourier::{
    FourierNtruDecryptWorkspace, FourierNtruEncryptWorkspace, FourierNtruGadgetEncryptWorkspace,
    FourierNtruSecretKey,
};
pub use ntt::{NttNtruGadgetEncryptWorkspace, NttNtruSecretKey};
