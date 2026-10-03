//! Same-secret conversion from coefficient NLev to transformed NGSW.

#[cfg(feature = "fourier")]
mod fourier;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::FourierNtruSchemeSwitchKey;
#[cfg(feature = "ntt")]
pub use ntt::NttNtruSchemeSwitchKey;
