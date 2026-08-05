//! GLWE secret key types organized by domain representation.

mod coeff;
mod fourier;
mod gadget;
mod ntt;

pub(crate) use crate::secret_key_type::encode_secret_polynomial_to;

pub use coeff::{GlweSecretKey, GlweSecretKeyParameterSet};
pub use fourier::{FourierGlweDecryptContext, FourierGlweEncryptContext, FourierGlweSecretKey};
pub use gadget::{FourierGadgetEncryptContext, NttGadgetEncryptContext};
pub use ntt::NttGlweSecretKey;
