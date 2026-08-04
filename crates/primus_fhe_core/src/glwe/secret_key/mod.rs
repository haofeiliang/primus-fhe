//! GLWE secret key types organized by domain representation.

mod coeff;
mod dcrt;
mod fourier;
mod gadget;
mod ntt;
mod signed;

pub(crate) use signed::{
    encode_secret_coefficient, encode_secret_polynomial_to, encode_secret_polynomial_to_rns,
};

pub use coeff::{GlweSecretKey, GlweSecretKeyParameterSet};
pub use dcrt::{DcrtGlweDecryptContext, DcrtGlweSecretKey};
pub use fourier::{FourierGlweDecryptContext, FourierGlweEncryptContext, FourierGlweSecretKey};
pub use gadget::{FourierGadgetEncryptContext, NttGadgetEncryptContext};
pub use ntt::NttGlweSecretKey;
pub use signed::SecretCoefficient;
