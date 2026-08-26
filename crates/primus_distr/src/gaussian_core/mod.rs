use primus_integer::{FheUint, Integer};

mod cdt;
mod parameters;
#[cfg(feature = "high_precision")]
mod precise_cdt;
mod ziggurat;

pub(crate) use cdt::build_cdt;
#[cfg(feature = "high_precision")]
pub(crate) use parameters::PRECISE_CDT_MAX_MAGNITUDE;
pub(crate) use parameters::{CDT_MAX_MAGNITUDE, DEFAULT_TAIL_CUT, GaussianParameters};
#[cfg(feature = "high_precision")]
pub(crate) use precise_cdt::{build_precise_cdt, compare_u256};
pub(crate) use ziggurat::ZigguratMagnitudeSampler;

/// Encodes a sampled magnitude in the canonical unsigned modulus range.
#[inline(always)]
pub(crate) fn encode_modular<T: FheUint>(positive: bool, magnitude: T, modulus_minus_one: T) -> T {
    if magnitude.is_zero() {
        T::ZERO
    } else if positive {
        magnitude
    } else {
        modulus_minus_one - magnitude + T::ONE
    }
}

/// Applies the sampled sign to a non-negative magnitude.
#[inline(always)]
pub(crate) fn encode_signed<T: Integer>(positive: bool, magnitude: T) -> T {
    if positive {
        magnitude
    } else {
        T::ZERO - magnitude
    }
}
