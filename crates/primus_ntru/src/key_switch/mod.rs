//! NTRU key switching through NLev external products.

mod fourier;
mod ntt;

pub use fourier::FourierNtruKeySwitchingKey;
pub use ntt::NttNtruKeySwitchingKey;
