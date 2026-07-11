//! GLWE secret key types organized by domain representation.

mod coeff;
mod crt;
mod dcrt;
mod fourier;
mod ntt;

pub use coeff::GlweSecretKey;
pub use crt::CrtGlweSecretKey;
pub use dcrt::{
    DcrtGlweDecryptContext, DcrtGlweDecryptContextRefMut, DcrtGlweSecretKey,
};
pub use fourier::FourierGlweSecretKey;
pub use ntt::NttGlweSecretKey;
