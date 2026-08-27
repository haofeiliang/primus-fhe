//! GLWE secret key types organized by domain representation.

mod coeff;
mod fourier;
mod gadget;
mod ntt;

use num_traits::Signed;
use primus_integer::{FheUint, SignedInteger};

use crate::SecretCoefficient;

pub use coeff::{GlweSecretKey, GlweSecretKeyParameterSet};
pub use fourier::{FourierGlweDecryptContext, FourierGlweEncryptContext, FourierGlweSecretKey};
pub use gadget::{FourierGadgetEncryptContext, NttGadgetEncryptContext};
pub use ntt::NttGlweSecretKey;

pub(crate) fn encode_secret_polynomial_to<T: FheUint>(
    coefficients: &[SecretCoefficient<T>],
    output: &mut [T],
    modulus: T,
) {
    assert_eq!(output.len(), coefficients.len());
    output
        .iter_mut()
        .zip(coefficients)
        .for_each(|(output, &coefficient)| {
            *output = if coefficient.is_negative() {
                debug_assert!(coefficient.unsigned_abs() < modulus);
                modulus.wrapping_add_signed(coefficient)
            } else {
                let coefficient = coefficient.cast_to_unsigned();
                debug_assert!(coefficient < modulus);
                coefficient
            };
        });
}
