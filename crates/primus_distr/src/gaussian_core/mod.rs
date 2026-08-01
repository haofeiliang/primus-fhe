use primus_integer::{FheUint, Integer};

mod cdt;
mod parameters;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
mod unix_cdt;
mod ziggurat;

pub(crate) use cdt::build_cdt;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
pub(crate) use parameters::UNIX_CDT_MAX_MAGNITUDE;
pub(crate) use parameters::{
    CDT_MAX_MAGNITUDE, CDT_STANDARD_DEVIATION_THRESHOLD, DEFAULT_TAIL_CUT, GaussianParameters,
};
#[cfg(all(target_os = "linux", feature = "high_precision"))]
pub(crate) use unix_cdt::{build_unix_cdt, compare_u256};
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

#[cfg(test)]
mod tests {
    use rand::{SeedableRng, distr::Distribution, rngs::StdRng};

    use crate::{DiscreteGaussian, SignedDiscreteGaussian};

    #[test]
    fn signed_and_modular_adapters_encode_the_same_samples() {
        for standard_deviation in [3.19, 30.0] {
            let modular = DiscreteGaussian::<u64>::new(standard_deviation, u64::MAX).unwrap();
            let signed = SignedDiscreteGaussian::<i64>::new(standard_deviation).unwrap();
            let mut modular_rng = StdRng::seed_from_u64(0x4449_5354_522d_3035);
            let mut signed_rng = StdRng::seed_from_u64(0x4449_5354_522d_3035);

            for _ in 0..256 {
                assert_eq!(
                    modular.sample(&mut modular_rng) as i64,
                    signed.sample(&mut signed_rng)
                );
            }
        }
    }
}
