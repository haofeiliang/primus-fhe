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

/// Distribution used to sample secret-key coefficients.
///
/// Individual cryptosystems may support only a subset of these distributions.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum SecretKeyDistr {
    /// Uniform binary coefficients in `{0, 1}`.
    Binary,
    /// Uniform ternary coefficients in `{-1, 0, 1}`.
    #[default]
    Ternary,
    /// Centered discrete Gaussian coefficients with the given standard deviation.
    Gaussian(f64),
}
