use primus_distr::{DiscreteGaussian, SecretKeySampler};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{RoundedCodec, SecretKeyDistr};

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
    /// **LWE** message modulus, refers to **t** in the paper.
    plain_modulus_value: T,
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
    /// Panics if `dimension` is zero or `dimension + 1` overflows `usize`,
    /// secret-key sampling violates [`SecretKeySampler::new`]'s validity rules,
    /// its support does not fit below the ciphertext modulus, the noise sampler
    /// violates [`DiscreteGaussian::new`]'s validity rules,
    /// or the plaintext/ciphertext moduli fail the rules of
    /// [`RoundedCodec::new`](primus_encoding::RoundedCodec::new).
    #[inline]
    pub fn new(
        dimension: usize,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        assert!(dimension != 0, "LWE dimension must be non-zero");
        dimension.checked_add(1).expect("LWE length overflow");
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one).unwrap();
        let secret_key_sampler = SecretKeySampler::new(secret_key_distr);
        assert!(
            secret_key_sampler.maximum_magnitude() <= cipher_modulus_minus_one,
            "secret-key magnitude bound must be less than the ciphertext modulus"
        );

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        let plaintext_codec = RoundedCodec::new(plain_modulus_value, cipher_modulus);

        Self {
            dimension,
            plain_modulus_value,
            cipher_modulus,
            cipher_modulus_minus_one,
            cipher_modulus_uniform_distr,
            plaintext_codec,
            secret_key_sampler,
            noise_distribution,
        }
    }

    /// Returns the dimension of this [`LweParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the plain modulus value of this [`LweParameters<T, M>`].
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.plain_modulus_value
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
