use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{LweSecretKeyType, PlaintextCodec};

/// Lwe Parameters.
#[derive(Clone)]
pub struct LweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// **LWE** vector dimension, refers to **n** in the paper.
    dimension: usize,
    /// **LWE** message modulus, refers to **t** in the paper.
    plain_modulus_value: T,
    plaintext_codec: PlaintextCodec<T>,
    /// **LWE** cipher modulus minus one, refers to **q-1** in the paper.
    cipher_modulus_minus_one: T,
    /// **LWE** cipher modulus, refers to **q** in the paper.
    cipher_modulus: M,
    cipher_modulus_uniform_distr: Uniform<T>,
    /// The distribution type of the LWE Secret Key.
    secret_key_type: LweSecretKeyType,
    /// The noise distribution.
    noise_distribution: DiscreteGaussian<T>,
}

impl<T, M> LweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a new [`LweParameters<T, M>`].
    #[inline]
    pub fn new(
        dimension: usize,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_type: LweSecretKeyType,
        noise_standard_deviation: f64,
    ) -> Self {
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one).unwrap();

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        let plaintext_codec = PlaintextCodec::new(plain_modulus_value, cipher_modulus.value());

        Self {
            dimension,
            plain_modulus_value,
            plaintext_codec,
            cipher_modulus_minus_one,
            cipher_modulus,
            cipher_modulus_uniform_distr,
            secret_key_type,
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

    /// Returns the preselected plaintext codec strategy.
    #[inline]
    pub fn plaintext_codec(&self) -> &PlaintextCodec<T> {
        &self.plaintext_codec
    }

    /// Returns the cipher modulus minus one of this [`LweParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.cipher_modulus_minus_one
    }

    /// Returns the cipher modulus of this [`LweParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the cipher modulus uniform distr of this [`LweParameters<T, M>`].
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.cipher_modulus_uniform_distr
    }

    /// Returns the secret key type of this [`LweParameters<T, M>`].
    #[inline]
    pub fn secret_key_type(&self) -> LweSecretKeyType {
        self.secret_key_type
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

    /// Gets the discrete gaussian noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32, min_sigma: f64) -> DiscreteGaussian<T> {
        let noise_standard_deviation = self.noise_standard_deviation();
        let var = noise_standard_deviation * noise_standard_deviation;
        let sigma = (var / count as f64).sqrt().max(min_sigma);
        DiscreteGaussian::new(sigma, self.cipher_modulus_minus_one).unwrap()
    }
}
