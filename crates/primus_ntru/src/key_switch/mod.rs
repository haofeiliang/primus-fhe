//! NTRU-to-NTRU gadget products and coefficient-domain conversion to independent LWE.

mod fourier;
mod lwe;
mod ntt;

pub use fourier::FourierNtruKeySwitchingKey;
pub use lwe::{NtruLweKeySwitchingKey, NtruLweKeySwitchingWorkspace};
pub use ntt::NttNtruKeySwitchingKey;
