use primus_integer::{AsInto, FheUint};
use rand::distr::Distribution;

use crate::{
    DistrErr,
    gaussian_core::{
        GaussianParameters, UNIX_CDT_MAX_MAGNITUDE, UnixCdtMagnitudeSampler, encode_modular,
    },
};

/// High-precision CDT sampler using 256-bit arithmetic (Unix only).
#[derive(Debug, Clone)]
pub struct UnixCDTSampler<T: FheUint> {
    core: UnixCdtMagnitudeSampler,
    modulus_minus_one: T,
}

impl<T: FheUint> UnixCDTSampler<T> {
    /// Generates a high-precision CDT sampler.
    ///
    /// Returns an error when the parameters are invalid, the support exceeds
    /// the high-precision CDT limit, or the modulus cannot encode it.
    pub fn new(std_dev: f64, tail_cut: f64, modulus_minus_one: T) -> Result<Self, DistrErr> {
        let parameters = GaussianParameters::new(std_dev, tail_cut)?;
        Self::from_parameters(parameters, modulus_minus_one)
    }

    pub(crate) fn from_parameters(
        parameters: GaussianParameters,
        modulus_minus_one: T,
    ) -> Result<Self, DistrErr> {
        let parameters = parameters
            .validate_cdt_size(UNIX_CDT_MAX_MAGNITUDE)?
            .validate_modular_output(modulus_minus_one)?;
        Ok(Self {
            core: UnixCdtMagnitudeSampler::new(parameters),
            modulus_minus_one,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.core.standard_deviation()
    }
}

impl<T: FheUint> Distribution<T> for UnixCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let (positive, magnitude) = self.core.sample(rng);
        encode_modular(positive, magnitude.as_into(), self.modulus_minus_one)
    }
}
