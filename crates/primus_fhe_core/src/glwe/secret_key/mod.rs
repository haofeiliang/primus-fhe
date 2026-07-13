//! GLWE secret key types organized by domain representation.

mod coeff;
mod crt;
mod dcrt;
mod fourier;
mod gadget;
mod ntt;

pub use coeff::GlweSecretKey;
pub use crt::CrtGlweSecretKey;
pub use dcrt::{DcrtGlweDecryptContext, DcrtGlweDecryptContextRefMut, DcrtGlweSecretKey};
pub use fourier::{FourierGlweDecryptContext, FourierGlweEncryptContext, FourierGlweSecretKey};
pub use gadget::{FourierGadgetEncryptContext, NttGadgetEncryptContext};
pub use ntt::NttGlweSecretKey;
