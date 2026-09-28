//! GLWE key switching across single-modulus and RNS representations.

mod fourier;
mod ntt;

pub use fourier::{FourierGlweKeySwitchingKey, FourierGlweKeySwitchingWorkspace};
pub use ntt::{NttGlweKeySwitchingKey, NttGlweKeySwitchingWorkspace};
