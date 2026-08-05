use num_traits::identities::ConstZero;
use primus_integer::{FheUint, UnsignedInteger, WrappingNeg};

/// Signed coefficient type used by canonical ring secret keys.
pub type SecretCoefficient<T> = <T as UnsignedInteger>::SignedInteger;

/// Encodes one small signed secret coefficient in `[0, modulus)`.
#[inline]
pub(crate) fn encode_secret_coefficient<T: FheUint>(
    coefficient: SecretCoefficient<T>,
    modulus: T,
) -> T {
    if coefficient < SecretCoefficient::<T>::ZERO {
        let magnitude = T::cast_from_signed(coefficient.wrapping_neg());
        debug_assert!(magnitude < modulus);
        modulus - magnitude
    } else {
        let coefficient = T::cast_from_signed(coefficient);
        debug_assert!(coefficient < modulus);
        coefficient
    }
}

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

/// The distribution type of the LWE Secret Key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum LweSecretKeyType {
    /// Binary SecretKey Distribution.
    Binary,
    /// Ternary SecretKey Distribution.
    #[default]
    Ternary,
}

/// The distribution type of the Ring Secret Key.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum RingSecretKeyType {
    /// Binary SecretKey Distribution.
    Binary,
    /// Ternary SecretKey Distribution.
    #[default]
    Ternary,
    /// Gaussian SecretKey Distribution.
    Gaussian(f64),
}
