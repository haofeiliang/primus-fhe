//! Same-secret conversion from coefficient NLev to transformed NGSW.

mod fourier;
mod ntt;

pub use fourier::FourierNtruSchemeSwitchKey;
pub use ntt::NttNtruSchemeSwitchKey;
