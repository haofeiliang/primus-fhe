use std::marker::PhantomData;

use primus_integer::{AsInto, Integer};
use rand::distr::Distribution;

use crate::{
    DistrErr,
    gaussian_core::{CDT_MAX_MAGNITUDE, CdtMagnitudeSampler, GaussianParameters, encode_signed},
};

/// Signed CDT sampler using log-space computation.
#[derive(Debug, Clone)]
pub struct SignedCDTSampler<T: Integer> {
    core: CdtMagnitudeSampler,
    output: PhantomData<T>,
}

impl<T: Integer> SignedCDTSampler<T> {
    /// Generates a signed CDT sampler using log-space arithmetic.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the portable CDT limit, or `T` cannot represent every signed sample.
    pub fn new(std_dev: f64, tail_cut: f64) -> Result<Self, DistrErr> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters)
    }

    pub(crate) fn from_parameters(parameters: GaussianParameters) -> Result<Self, DistrErr> {
        let parameters = parameters
            .validate_cdt_size(CDT_MAX_MAGNITUDE)?
            .validate_signed_output::<T>()?;
        Ok(Self {
            core: CdtMagnitudeSampler::new(parameters),
            output: PhantomData,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.core.standard_deviation()
    }
}

impl<T: Integer> Distribution<T> for SignedCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.core.sample(rng);
        encode_signed(positive, magnitude.as_into())
    }
}
