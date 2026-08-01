use primus_integer::Integer;

use crate::DistrErr;

/// Default number of standard deviations retained by facade samplers.
pub(crate) const DEFAULT_TAIL_CUT: f64 = 12.0;
/// Largest standard deviation for which facade samplers select portable CDT.
pub(crate) const CDT_STANDARD_DEVIATION_THRESHOLD: f64 = 20.0;
/// Largest magnitude supported by the portable 64-bit CDT representation.
pub(crate) const CDT_MAX_MAGNITUDE: u64 = 255;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
/// Largest magnitude supported by the Linux 256-bit CDT representation.
pub(crate) const UNIX_CDT_MAX_MAGNITUDE: u64 = 1023;

/// Smallest scale for which this crate treats the discrete distribution's
/// measured standard deviation as matching the requested value closely.
///
/// This is an implementation-support threshold, not a mathematical or
/// cryptographic security bound. Below it, lattice discretization makes the
/// measured standard deviation diverge increasingly from the scale parameter.
const MIN_SUPPORTED_STANDARD_DEVIATION: f64 = 0.7;

/// `2^64`, represented exactly as `f64`.
///
/// This is the exclusive range end checked before converting a floating-point
/// magnitude to `u64`; an out-of-range Rust `as` conversion would otherwise
/// saturate to [`u64::MAX`] and hide the invalid support size.
const U64_RANGE_END_AS_F64: f64 = 18_446_744_073_709_551_616.0;

/// Validated numerical parameters shared by all Gaussian backends.
///
/// Construction establishes that the standard deviation, tail cut, variance,
/// and twice-variance used by the sampling recurrences are finite. The support
/// bound is `max(1, floor(standard_deviation * tail_cut))` and is representable
/// as `u64`. Backend-specific table limits and output representations are
/// validated separately before any sampler is built.
#[derive(Clone, Copy)]
pub(crate) struct GaussianParameters {
    /// Standard deviation of the centered Gaussian.
    standard_deviation: f64,
    /// Number of standard deviations retained on each side of zero.
    tail_cut: f64,
    /// Cached inclusive upper bound of the truncated support.
    maximum_magnitude: u64,
}

impl GaussianParameters {
    /// Validates the common floating-point parameter domain and derives the
    /// inclusive maximum sample magnitude.
    ///
    /// Returns [`DistrErr::InvalidStandardDeviation`] or
    /// [`DistrErr::InvalidTailCut`] when a floating-point recurrence would be
    /// undefined, and [`DistrErr::MaximumMagnitudeTooLarge`] when the truncated
    /// support cannot be represented as a `u64` magnitude.
    pub(crate) fn new(standard_deviation: f64, tail_cut: f64) -> Result<Self, DistrErr> {
        let variance = standard_deviation * standard_deviation;
        if !standard_deviation.is_finite()
            || standard_deviation < MIN_SUPPORTED_STANDARD_DEVIATION
            || !variance.is_finite()
            || !(2.0 * variance).is_finite()
        {
            return Err(DistrErr::InvalidStandardDeviation {
                value: standard_deviation,
            });
        }
        if !tail_cut.is_finite() || tail_cut <= 0.0 {
            return Err(DistrErr::InvalidTailCut { value: tail_cut });
        }

        let maximum_magnitude = (standard_deviation * tail_cut).floor();
        if !maximum_magnitude.is_finite() || maximum_magnitude >= U64_RANGE_END_AS_F64 {
            return Err(DistrErr::MaximumMagnitudeTooLarge {
                standard_deviation,
                tail_cut,
            });
        }

        Ok(Self {
            standard_deviation,
            tail_cut,
            maximum_magnitude: (maximum_magnitude as u64).max(1),
        })
    }

    /// Returns the validated standard deviation.
    #[inline]
    pub(crate) fn standard_deviation(self) -> f64 {
        self.standard_deviation
    }

    /// Returns the validated tail cut.
    #[inline]
    pub(crate) fn tail_cut(self) -> f64 {
        self.tail_cut
    }

    /// Returns the inclusive maximum magnitude in the truncated support.
    ///
    /// This cached bound is derived once during construction as
    /// `max(1, floor(standard_deviation * tail_cut))`; it is not an independent
    /// caller-supplied parameter.
    #[inline]
    pub(crate) fn maximum_magnitude(self) -> u64 {
        self.maximum_magnitude
    }

    /// Verifies that the support fits a CDT backend whose largest supported
    /// magnitude is `maximum`.
    ///
    /// Returning `Self` allows this proof to be chained with output-domain
    /// validation before allocating the table.
    pub(crate) fn validate_cdt_size(self, maximum: u64) -> Result<Self, DistrErr> {
        let maximum_magnitude = self.maximum_magnitude();
        if maximum_magnitude > maximum {
            return Err(DistrErr::CdtTableTooLarge {
                maximum_magnitude,
                supported_maximum: maximum,
            });
        }
        Ok(self)
    }

    /// Verifies that every magnitude can be encoded modulo
    /// `modulus_minus_one + 1`.
    ///
    /// The resulting invariant `maximum_magnitude <= modulus_minus_one` makes
    /// the negative encoding `modulus_minus_one - magnitude + 1` non-underflowing
    /// and canonical.
    pub(crate) fn validate_modular_output<T: Integer>(
        self,
        modulus_minus_one: T,
    ) -> Result<Self, DistrErr> {
        let modulus_minus_one: u128 = modulus_minus_one.as_into();
        let maximum_magnitude = self.maximum_magnitude();
        if u128::from(maximum_magnitude) > modulus_minus_one {
            return Err(DistrErr::ModulusTooSmall {
                maximum_magnitude,
                modulus_minus_one,
            });
        }
        Ok(self)
    }

    /// Verifies that `T` is signed and can represent both signs of every
    /// magnitude in the truncated support.
    ///
    /// Bounding the magnitude by `T::MAX` ensures that conversion and
    /// subsequent negation cannot overflow.
    pub(crate) fn validate_signed_output<T: Integer>(self) -> Result<Self, DistrErr> {
        if T::MIN >= T::ZERO {
            return Err(DistrErr::UnsignedOutputType);
        }

        let output_maximum: u128 = T::MAX.as_into();
        let maximum_magnitude = self.maximum_magnitude();
        if u128::from(maximum_magnitude) > output_maximum {
            return Err(DistrErr::OutputTypeTooNarrow {
                maximum_magnitude,
                output_maximum,
            });
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{CDT_MAX_MAGNITUDE, GaussianParameters};
    use crate::DistrErr;

    #[test]
    fn rejects_invalid_parameters_and_unencodable_support() {
        for standard_deviation in [
            0.0,
            -1.0,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::MAX,
        ] {
            assert!(matches!(
                GaussianParameters::new(standard_deviation, 12.0),
                Err(DistrErr::InvalidStandardDeviation { .. })
            ));
        }
        for tail_cut in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert!(matches!(
                GaussianParameters::new(3.19, tail_cut),
                Err(DistrErr::InvalidTailCut { .. })
            ));
        }
        assert!(matches!(
            GaussianParameters::new(1.0e10, 1.0e10),
            Err(DistrErr::MaximumMagnitudeTooLarge { .. })
        ));

        let parameters = GaussianParameters::new(3.19, 12.0).unwrap();
        assert!(matches!(
            parameters.validate_modular_output(37_u16),
            Err(DistrErr::ModulusTooSmall { .. })
        ));
        assert!(parameters.validate_modular_output(38_u16).is_ok());
        assert!(matches!(
            parameters.validate_signed_output::<u16>(),
            Err(DistrErr::UnsignedOutputType)
        ));
        assert!(parameters.validate_signed_output::<i16>().is_ok());

        let large_parameters = GaussianParameters::new(30.0, 12.0).unwrap();
        assert!(matches!(
            large_parameters.validate_cdt_size(CDT_MAX_MAGNITUDE),
            Err(DistrErr::CdtTableTooLarge { .. })
        ));
        assert!(matches!(
            large_parameters.validate_signed_output::<i8>(),
            Err(DistrErr::OutputTypeTooNarrow { .. })
        ));
    }
}
