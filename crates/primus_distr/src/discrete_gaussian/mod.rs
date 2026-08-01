use primus_integer::FheUint;
use rand::{Rng, distr::Distribution};

mod cdt;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
mod unix_cdt;
mod ziggurat;

pub use cdt::CDTSampler;
#[cfg(all(target_os = "linux", feature = "high_precision"))]
pub use unix_cdt::UnixCDTSampler;
pub use ziggurat::DiscreteZiggurat;

use crate::{
    DistrErr,
    gaussian::{CDT_STANDARD_DEVIATION_THRESHOLD, DEFAULT_TAIL_CUT, GaussianParameters},
};

/// A centered discrete Gaussian distribution over unsigned integers.
///
/// Samples are non-negative. Negative values from the underlying distribution
/// are mapped into the upper half of the modulus range via
/// `modulus_minus_one - |x| + 1`.
///
/// Internally delegates to [`CDTSampler`] (σ ≤ 20) or
/// [`DiscreteZiggurat`] (σ > 20).
#[derive(Clone)]
pub enum DiscreteGaussian<T: FheUint> {
    /// CDT (cumulative distribution table) based sampler.
    Cdt(CDTSampler<T>),
    /// Ziggurat based sampler.
    Ziggurat(DiscreteZiggurat<T>),
}

impl<T: FheUint> DiscreteGaussian<T> {
    /// Construct a discrete Gaussian sampler.
    ///
    /// Automatically selects the CDT or Ziggurat backend based on `std_dev`.
    ///
    /// # Parameters
    /// - `std_dev` — standard deviation (`σ`), must be at least 0.7.
    /// - `modulus_minus_one` — the modulus minus one, used to wrap negative
    ///   samples into the unsigned range.
    ///
    /// # Errors
    ///
    /// Returns an error when `std_dev` is smaller than 0.7 or cannot be used by
    /// the floating-point kernels, or when the truncated support does not fit
    /// below the supplied modulus.
    #[inline]
    pub fn new(std_dev: f64, modulus_minus_one: T) -> Result<DiscreteGaussian<T>, DistrErr> {
        let parameters = GaussianParameters::new(std_dev, DEFAULT_TAIL_CUT)?;
        if std_dev <= CDT_STANDARD_DEVIATION_THRESHOLD {
            CDTSampler::from_parameters(parameters, modulus_minus_one).map(DiscreteGaussian::Cdt)
        } else {
            DiscreteZiggurat::from_parameters(parameters, modulus_minus_one)
                .map(DiscreteGaussian::Ziggurat)
        }
    }

    /// Returns the standard deviation of this [`DiscreteGaussian<T>`].
    pub fn standard_deviation(&self) -> f64 {
        match self {
            DiscreteGaussian::Cdt(sampler) => sampler.std_dev(),
            DiscreteGaussian::Ziggurat(sampler) => sampler.std_dev(),
        }
    }
}

impl<T: FheUint> Distribution<T> for DiscreteGaussian<T> {
    #[inline]
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> T {
        match self {
            DiscreteGaussian::Cdt(sampler) => sampler.sample(rng),
            DiscreteGaussian::Ziggurat(sampler) => sampler.sample(rng),
        }
    }
}
