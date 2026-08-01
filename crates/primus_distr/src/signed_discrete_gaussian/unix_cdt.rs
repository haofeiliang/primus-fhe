use std::marker::PhantomData;

use primus_integer::{AsInto, Integer};
use rand::distr::Distribution;

use crate::{
    DistrErr,
    gaussian_core::{
        GaussianParameters, UNIX_CDT_MAX_MAGNITUDE, UnixCdtMagnitudeSampler, encode_signed,
    },
};

/// High-precision signed CDT sampler using 256-bit arithmetic (Unix only).
#[derive(Debug, Clone)]
pub struct SignedUnixCDTSampler<T: Integer> {
    core: UnixCdtMagnitudeSampler,
    output: PhantomData<T>,
}

impl<T: Integer> SignedUnixCDTSampler<T> {
    /// Generates a high-precision signed CDT sampler.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the high-precision CDT limit, or `T` cannot represent it.
    pub fn new(std_dev: f64, tail_cut: f64) -> Result<Self, DistrErr> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters)
    }

    pub(crate) fn from_parameters(parameters: GaussianParameters) -> Result<Self, DistrErr> {
        let parameters = parameters
            .validate_cdt_size(UNIX_CDT_MAX_MAGNITUDE)?
            .validate_signed_output::<T>()?;
        Ok(Self {
            core: UnixCdtMagnitudeSampler::new(parameters),
            output: PhantomData,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.core.standard_deviation()
    }
}

impl<T: Integer> Distribution<T> for SignedUnixCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.core.sample(rng);
        encode_signed(positive, magnitude.as_into())
    }
}
