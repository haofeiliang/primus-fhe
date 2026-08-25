use primus_integer::FheInt;
use rand::distr::Distribution;

use crate::{
    DistrErr,
    gaussian_core::{CDT_STANDARD_DEVIATION_THRESHOLD, DEFAULT_TAIL_CUT, GaussianParameters},
};

mod cdt;
#[cfg(feature = "high_precision")]
mod precise_cdt;
mod ziggurat;

pub use cdt::SignedCDTSampler;
#[cfg(feature = "high_precision")]
pub use precise_cdt::SignedPreciseCDTSampler;
pub use ziggurat::SignedDiscreteZiggurat;

/// A centered discrete Gaussian distribution over signed integers.
///
/// Samples can be positive, zero, or negative. Internally delegates to
/// [`SignedCDTSampler`] (σ ≤ 20) or [`SignedDiscreteZiggurat`] (σ > 20).
#[derive(Clone)]
pub enum SignedDiscreteGaussian<T: FheInt> {
    /// CDT (cumulative distribution table) based sampler.
    Cdt(SignedCDTSampler<T>),
    /// Ziggurat based sampler.
    Ziggurat(SignedDiscreteZiggurat<T>),
}

impl<T: FheInt> SignedDiscreteGaussian<T> {
    /// Construct a signed discrete Gaussian sampler.
    ///
    /// Automatically selects the CDT or Ziggurat backend based on `std_dev`.
    ///
    /// # Parameters
    /// - `std_dev` — standard deviation (`σ`), which must be finite and at
    ///   least 0.7.
    ///
    /// # Errors
    ///
    /// Returns an error when `std_dev` is invalid or the truncated support
    /// cannot be represented by `T`.
    #[inline]
    pub fn new(std_dev: f64) -> Result<SignedDiscreteGaussian<T>, DistrErr> {
        let parameters = GaussianParameters::new(std_dev, DEFAULT_TAIL_CUT)?;
        if std_dev <= CDT_STANDARD_DEVIATION_THRESHOLD {
            SignedCDTSampler::from_parameters(parameters).map(SignedDiscreteGaussian::Cdt)
        } else {
            SignedDiscreteZiggurat::from_parameters(parameters)
                .map(SignedDiscreteGaussian::Ziggurat)
        }
    }

    /// Returns the standard deviation of this [`SignedDiscreteGaussian<T>`].
    pub fn standard_deviation(&self) -> f64 {
        match self {
            SignedDiscreteGaussian::Cdt(sampler) => sampler.std_dev(),
            SignedDiscreteGaussian::Ziggurat(sampler) => sampler.std_dev(),
        }
    }
}

impl<T: FheInt> Distribution<T> for SignedDiscreteGaussian<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        match self {
            SignedDiscreteGaussian::Cdt(sampler) => sampler.sample(rng),
            SignedDiscreteGaussian::Ziggurat(sampler) => sampler.sample(rng),
        }
    }
}
