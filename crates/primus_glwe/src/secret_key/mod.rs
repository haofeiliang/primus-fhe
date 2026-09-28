//! GLWE secret key types organized by domain representation.

mod coeff;
mod fourier;
mod ntt;

pub use coeff::GlweSecretKey;
pub use fourier::{
    FourierGlweDecryptWorkspace, FourierGlweEncryptWorkspace, FourierGlweGadgetEncryptWorkspace,
    FourierGlweSecretKey,
};
pub use ntt::{NttGlweGadgetEncryptWorkspace, NttGlweSecretKey};
