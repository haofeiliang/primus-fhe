//! GLWE secret key types organized by domain representation.

mod coeff;
mod fourier;
mod gadget;
mod ntt;

use num_traits::ConstZero;
use primus_integer::{FheUint, WrappingNeg};

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
            *output = if coefficient < SecretCoefficient::<T>::ZERO {
                let magnitude = T::cast_from_signed(coefficient.wrapping_neg());
                debug_assert!(magnitude < modulus);
                modulus - magnitude
            } else {
                let coefficient = T::cast_from_signed(coefficient);
                debug_assert!(coefficient < modulus);
                coefficient
            };
        });
}
