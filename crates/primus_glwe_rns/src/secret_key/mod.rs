//! DCRT-domain GLWE secret keys.

mod dcrt;

use num_traits::Signed;
use primus_integer::{FheUint, SignedInteger};

use crate::{GlweSecretKey, SecretCoefficient};

pub use dcrt::{DcrtGlweDecryptContext, DcrtGlweSecretKey};

#[inline]
pub(crate) fn encode_secret_coefficient<T: FheUint>(
    coefficient: SecretCoefficient<T>,
    modulus: T,
) -> T {
    if coefficient.is_negative() {
        debug_assert!(coefficient.unsigned_abs() < modulus);
        modulus.wrapping_add_signed(coefficient)
    } else {
        let coefficient = coefficient.cast_to_unsigned();
        debug_assert!(coefficient < modulus);
        coefficient
    }
}

fn encode_secret_polynomial_to<T: FheUint>(
    coefficients: &[SecretCoefficient<T>],
    output: &mut [T],
    modulus: T,
) {
    assert_eq!(output.len(), coefficients.len());
    output
        .iter_mut()
        .zip(coefficients)
        .for_each(|(output, &coefficient)| {
            *output = encode_secret_coefficient::<T>(coefficient, modulus);
        });
}

pub(crate) fn encode_secret_polynomial_to_rns<T: FheUint>(
    coefficients: &[SecretCoefficient<T>],
    output: &mut [T],
    moduli: &[T],
) {
    assert_eq!(output.len(), coefficients.len() * moduli.len());
    output
        .chunks_exact_mut(coefficients.len())
        .zip(moduli)
        .for_each(|(modulus_limb, &modulus)| {
            encode_secret_polynomial_to(coefficients, modulus_limb, modulus);
        });
}
