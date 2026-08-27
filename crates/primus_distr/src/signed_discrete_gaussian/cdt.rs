use std::marker::PhantomData;

use primus_integer::{AsInto, SignedInteger};
use rand::distr::Distribution;

use crate::{
    DistrErr,
    gaussian_core::{CDT_MAX_MAGNITUDE, GaussianParameters, build_cdt},
    utils::cdt_index_by,
};

/// Signed CDT sampler using log-space computation.
#[derive(Debug, Clone)]
pub struct SignedCDTSampler<T: SignedInteger> {
    std_dev: f64,
    cdt: Vec<u64>,
    output: PhantomData<T>,
}

impl<T: SignedInteger> SignedCDTSampler<T> {
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
        let (std_dev, cdt) = build_cdt(parameters);
        Ok(Self {
            std_dev,
            cdt,
            output: PhantomData,
        })
    }

    /// Returns the standard deviation of this sampler.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        self.std_dev
    }
}

impl<T: SignedInteger> Distribution<T> for SignedCDTSampler<T> {
    #[inline]
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> T {
        let random: u64 = rng.next_u64();
        let positive = random & 1 == 1;
        let index = cdt_index_by(&self.cdt, &random, Ord::cmp);
        let value: T = index.as_into();

        if value.is_zero() {
            return T::ZERO;
        }

        if positive { value } else { T::ZERO - value }
    }
}
