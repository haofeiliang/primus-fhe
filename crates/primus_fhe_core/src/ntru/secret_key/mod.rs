//! NTRU secret key types.

mod coeff;
mod ntt;

pub use coeff::NtruSecretKey;
pub use ntt::NttNtruSecretKey;
