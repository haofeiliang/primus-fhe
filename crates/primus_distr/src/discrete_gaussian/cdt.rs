use primus_integer::{AsInto, FheUint};
use rand::distr::Distribution;

use crate::{
    DistrErr,
    gaussian_core::{CDT_MAX_MAGNITUDE, CdtMagnitudeSampler, GaussianParameters, encode_modular},
};

/// CDT sampler using log-space computation.
#[derive(Debug, Clone)]
pub struct CDTSampler<T: FheUint> {
    core: CdtMagnitudeSampler,
    modulus_minus_one: T,
}

impl<T: FheUint> CDTSampler<T> {
    /// Generates a CDT sampler using log-space arithmetic.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the portable CDT limit, or the modulus cannot encode every magnitude.
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Result<Self, DistrErr> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters, modulus_minus_one)
    }

    pub(crate) fn from_parameters(
        parameters: GaussianParameters,
        modulus_minus_one: T,
    ) -> Result<Self, DistrErr> {
        let parameters = parameters
            .validate_cdt_size(CDT_MAX_MAGNITUDE)?
            .validate_modular_output(modulus_minus_one)?;
        Ok(Self {
            core: CdtMagnitudeSampler::new(parameters),
            modulus_minus_one,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.core.standard_deviation()
    }
}

impl<T: FheUint> Distribution<T> for CDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.core.sample(rng);
        encode_modular(positive, magnitude.as_into(), self.modulus_minus_one)
    }
}
