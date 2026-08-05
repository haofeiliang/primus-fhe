//! GLWE key switching across single-modulus and RNS representations.

mod fourier;
mod ntt;

pub use fourier::{FourierGlweKeySwitchingContext, FourierGlweKeySwitchingKey};
pub use ntt::{NttGlweKeySwitchingContext, NttGlweKeySwitchingKey};
