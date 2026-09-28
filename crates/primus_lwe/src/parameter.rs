use primus_distr::{DiscreteGaussian, SecretKeySampler};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{RoundedCodec, SecretKeyDistr};

/// Invalid LWE layout, encoding or sampling parameters.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum LweParameterError {
    /// The dimension is zero or its mask/body length overflows.
    #[error("LWE dimension must be nonzero and dimension + 1 must fit usize")]
    InvalidDimension,
    /// Invalid message/ciphertext moduli.
    #[error(transparent)]
    Encoding(#[from] primus_encoding::CodecError),
    /// Invalid secret sampling configuration, weight or output modulus.
    #[error(transparent)]
    SecretKey(#[from] primus_distr::SecretKeySamplerError),
    /// Invalid coefficient-domain Gaussian noise.
    #[error("invalid LWE noise distribution")]
    Noise(#[from] primus_distr::GaussianError),
}

/// Parameters and precomputed samplers for LWE with a nonzero vector dimension.
/// The ciphertext length `dimension + 1` always fits in `usize`.
#[derive(Clone)]
pub struct LweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Nonzero **LWE** vector dimension, refers to **n** in the paper.
    dimension: usize,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    cipher_modulus: M,
    /// **LWE** cipher modulus minus one, refers to **q-1** in the paper.
    cipher_modulus_minus_one: T,
    cipher_modulus_uniform_distr: Uniform<T>,
    plaintext_codec: RoundedCodec<T, M>,
    secret_key_sampler: SecretKeySampler<T>,
    /// The noise distribution.
    noise_distribution: DiscreteGaussian<T>,
}

impl<T, M> LweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a new [`LweParameters<T, M>`].
    ///
    /// # Panics
    ///
    /// Panics on the layout, encoding or sampler errors of [`Self::try_new`],
    /// including fixed secret weights exceeding the dimension.
    #[must_use]
    #[inline]
    pub fn new(
        dimension: usize,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            dimension,
            plain_modulus_value,
            cipher_modulus,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid LWE parameters")
    }

    /// Checks the dimension, encoding, secret support/weight and noise sampler.
    /// Noise standard deviation is measured in ciphertext coefficient units.
    /// Successful construction does not establish security or a decryption margin.
    pub fn try_new(
        dimension: usize,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, LweParameterError> {
        if dimension == 0 || dimension.checked_add(1).is_none() {
            return Err(LweParameterError::InvalidDimension);
        }
        let plaintext_codec = RoundedCodec::try_new(plain_modulus_value, cipher_modulus)?;
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one)?;
        let secret_key_sampler = SecretKeySampler::try_new(secret_key_distr)?;
        secret_key_sampler.validate_length(dimension)?;
        secret_key_sampler.validate_modulus(cipher_modulus_minus_one)?;

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        Ok(Self {
            dimension,
            cipher_modulus,
            cipher_modulus_minus_one,
            cipher_modulus_uniform_distr,
            plaintext_codec,
            secret_key_sampler,
            noise_distribution,
        })
    }

    /// Returns the dimension of this [`LweParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the plain modulus value of this [`LweParameters<T, M>`].
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.plaintext_codec.plaintext_modulus()
    }

    /// Returns the cipher modulus of this [`LweParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the representable ciphertext modulus, or `None` for a native torus.
    #[must_use]
    #[inline]
    pub fn cipher_modulus_value(&self) -> Option<T> {
        self.cipher_modulus.explicit_value()
    }

    /// Returns the cipher modulus minus one of this [`LweParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.cipher_modulus_minus_one
    }

    /// Returns the cipher modulus uniform distr of this [`LweParameters<T, M>`].
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.cipher_modulus_uniform_distr
    }

    /// Returns the preselected plaintext codec strategy.
    #[inline]
    pub fn plaintext_codec(&self) -> &RoundedCodec<T, M> {
        &self.plaintext_codec
    }

    /// Returns the secret key type of this [`LweParameters<T, M>`].
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_sampler.distr()
    }

    #[inline]
    pub(crate) fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        &self.secret_key_sampler
    }

    /// Returns the noise standard deviation of this [`LweParameters<T, M>`].
    #[inline]
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_distribution.standard_deviation()
    }

    /// Gets the discrete gaussian noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }
}
