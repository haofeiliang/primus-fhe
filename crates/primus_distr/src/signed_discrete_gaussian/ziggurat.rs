use primus_integer::{FheInt, SignedInteger};
use rand::distr::Distribution;

use crate::{
    DistrErr,
    gaussian_core::{GaussianParameters, ZigguratMagnitudeSampler, encode_signed},
};

/// Discrete Ziggurat sampler with signed output.
#[derive(Clone)]
pub struct SignedDiscreteZiggurat<T: FheInt + SignedInteger> {
    core: ZigguratMagnitudeSampler<T>,
}

impl<T: FheInt + SignedInteger> SignedDiscreteZiggurat<T> {
    /// Generates a [`SignedDiscreteZiggurat<T>`].
    ///
    /// Returns an error when the parameters are invalid, `T` cannot represent
    /// the signed support, or Ziggurat setup cannot represent the distribution.
    pub fn new(std_dev: f64, tail_cut: f64) -> Result<Self, DistrErr> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters)
    }

    pub(crate) fn from_parameters(parameters: GaussianParameters) -> Result<Self, DistrErr> {
        let parameters = parameters.validate_signed_output::<T>()?;
        Ok(Self {
            core: ZigguratMagnitudeSampler::new(parameters)?,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.core.standard_deviation()
    }
}

impl<T: FheInt + SignedInteger> Distribution<T> for SignedDiscreteZiggurat<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.core.sample(rng);
        encode_signed(positive, magnitude)
    }
}
