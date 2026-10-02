//! Modulus and sampling state shared by ordinary and gadget GLWE parameters.

use primus_distr::{DiscreteGaussian, SecretKeySampler};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use super::GlweParameterError;
use crate::SecretKeyDistr;

/// GLWE encryption parameters shared by ordinary and gadget ciphertexts.
///
/// Ciphertext sizes and plaintext encoding intentionally live in their
/// respective outer parameter types. Ordinary and derived gadget parameters
/// share this immutable state through [`std::sync::Arc`]; cloning the inner
/// directly still copies its sampler tables.
#[derive(Clone)]
pub struct GlweParametersInner<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    cipher_modulus: M,
    cipher_modulus_minus_one: T,
    cipher_modulus_uniform_distr: Uniform<T>,
    secret_key_sampler: SecretKeySampler<T>,
    noise_distribution: DiscreteGaussian<T>,
}

impl<T, M> PartialEq for GlweParametersInner<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.cipher_modulus == other.cipher_modulus
            && self.secret_key_distr() == other.secret_key_distr()
            && self.noise_distribution.standard_deviation()
                == other.noise_distribution.standard_deviation()
    }
}

impl<T, M> GlweParametersInner<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates GLWE encryption and secret-key parameters without ciphertext
    /// sizes or plaintext encoding.
    ///
    /// # Panics
    ///
    /// Panics if the secret-key sampler violates [`SecretKeySampler::new`]'s
    /// validity rules, its support does not fit below the ciphertext modulus,
    /// or the noise sampler violates [`DiscreteGaussian::new`]'s.
    /// Fixed secret-key weights are checked against the complete key length
    /// when sampling.
    #[must_use]
    pub fn new(
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(cipher_modulus, secret_key_distr, noise_standard_deviation)
            .expect("invalid GLWE parameters")
    }

    /// Prepares coefficient-unit noise and secret sampling, checking support
    /// against the ciphertext modulus. Fixed weights require the outer layout
    /// or an actual sampling length; this type has neither.
    pub fn try_new(
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, GlweParameterError> {
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one)?;

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        let secret_key_sampler = SecretKeySampler::try_new(secret_key_distr)?;
        secret_key_sampler.validate_modulus(cipher_modulus_minus_one)?;

        Ok(Self {
            cipher_modulus,
            cipher_modulus_minus_one,
            cipher_modulus_uniform_distr,
            secret_key_sampler,
            noise_distribution,
        })
    }

    /// Returns the cipher modulus.
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the explicit ciphertext modulus, or `None` for the native modulus
    /// `2^T::BITS`, whose value cannot be represented in `T`.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.cipher_modulus.explicit_value()
    }

    /// Returns the cipher modulus minus one.
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.cipher_modulus_minus_one
    }

    /// Returns the uniform distribution over the ciphertext modulus.
    #[inline]
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.cipher_modulus_uniform_distr
    }

    /// Returns the secret-key distribution type.
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_sampler.distr()
    }

    /// Returns shared precomputation for signed and encoded secret coefficients.
    #[must_use]
    #[inline]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        &self.secret_key_sampler
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }

    /// Returns noise with standard deviation `max(sigma / sqrt(count), min_sigma)`.
    ///
    /// # Panics
    ///
    /// Panics if the resulting standard deviation is rejected by [`DiscreteGaussian::new`].
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32, min_sigma: f64) -> DiscreteGaussian<T> {
        let noise_standard_deviation = self.noise_distribution.standard_deviation();
        let var = noise_standard_deviation * noise_standard_deviation;
        let sigma = (var / count as f64).sqrt().max(min_sigma);
        DiscreteGaussian::new(sigma, self.cipher_modulus_minus_one).unwrap()
    }
}
