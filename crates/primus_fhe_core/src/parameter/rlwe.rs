use primus_decompose::primitive::ApproxSignedBasis;
use primus_distr::DiscreteGaussian;
use primus_factor::ShoupFactor;
use primus_integer::FheUint;
use primus_reduce::FieldContext;
use rand::distr::Uniform;

use crate::{PlaintextCodec, SecretKeyDistr};

/// Rlwe Parameters.
#[derive(Clone)]
pub struct RlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// The polynomial length, refers to **N** in the paper.
    poly_length: usize,
    /// **RLWE** message modulus, refers to **t** in the paper.
    plain_modulus_value: T,
    plaintext_codec: PlaintextCodec<T>,
    /// **RLWE** cipher modulus minus one, refers to **Q-1**.
    cipher_modulus_minus_one: T,
    /// The modulus, refers to **Q** in the paper.
    cipher_modulus: M,
    cipher_modulus_uniform_distr: Uniform<T>,
    delta: T,
    delta_factor: ShoupFactor<T>,
    /// The distribution type of the secret key.
    secret_key_distr: SecretKeyDistr,
    secret_key_distribution: Option<DiscreteGaussian<T>>,
    /// The noise's distribution.
    noise_distribution: DiscreteGaussian<T>,
}

impl<T, M> RlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a new [`RlweParameters<T, M>`].
    #[inline]
    pub fn new(
        poly_length: usize,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one).unwrap();

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        let plaintext_codec =
            PlaintextCodec::new(plain_modulus_value, Some(cipher_modulus.value()));

        let cipher_modulus_value = cipher_modulus.value();
        let (mut delta, rem) = cipher_modulus_value.div_rem(plain_modulus_value);
        if rem > (plain_modulus_value - T::ONE) / T::TWO {
            delta += T::ONE;
        }

        let delta_factor = ShoupFactor::new(delta, cipher_modulus_value);

        let secret_key_distribution =
            if let SecretKeyDistr::Gaussian(standard_deviation) = secret_key_distr {
                Some(DiscreteGaussian::new(standard_deviation, cipher_modulus_minus_one).unwrap())
            } else {
                None
            };

        Self {
            poly_length,
            plain_modulus_value,
            plaintext_codec,
            cipher_modulus_minus_one,
            cipher_modulus,
            cipher_modulus_uniform_distr,
            delta,
            delta_factor,
            secret_key_distr,
            secret_key_distribution,
            noise_distribution,
        }
    }

    /// Returns the poly length of this [`RlweParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the plain modulus value of this [`RlweParameters<T, M>`].
    pub fn plain_modulus_value(&self) -> T {
        self.plain_modulus_value
    }

    /// Returns the preselected plaintext codec strategy.
    #[inline]
    pub fn plaintext_codec(&self) -> &PlaintextCodec<T> {
        &self.plaintext_codec
    }

    /// Returns the cipher modulus of this [`RlweParameters<T, M>`].
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the cipher modulus of this [`RlweParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus_value(&self) -> T {
        self.cipher_modulus.value()
    }

    /// Returns the cipher modulus minus one of this [`RlweParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.cipher_modulus_minus_one
    }

    /// Returns the cipher modulus uniform distr of this [`RlweParameters<T, M>`].
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.cipher_modulus_uniform_distr
    }

    /// Returns the delta of this [`RlweParameters<T, M>`].
    pub fn delta(&self) -> T {
        self.delta
    }

    /// Returns the delta factor of this [`RlweParameters<T, M>`].
    pub fn delta_factor(&self) -> ShoupFactor<T> {
        self.delta_factor
    }

    /// Returns the secret key type of this [`RlweParameters<T, M>`].
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_distr
    }

    /// Returns the secret key distribution of this [`RlweParameters<T, M>`].
    pub fn secret_key_distribution(&self) -> Option<&DiscreteGaussian<T>> {
        self.secret_key_distribution.as_ref()
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }

    /// Returns the noise standard deviation of this [`RlweParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_distribution.standard_deviation()
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32, min_sigma: f64) -> DiscreteGaussian<T> {
        let noise_standard_deviation = self.noise_standard_deviation();
        let var = noise_standard_deviation * noise_standard_deviation;
        let sigma = (var / count as f64).sqrt().max(min_sigma);
        DiscreteGaussian::new(sigma, self.cipher_modulus_minus_one).unwrap()
    }
}

/// Rlev Parameters.
#[derive(Clone)]
pub struct RlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// The dimension, refers to **N** in the paper.
    pub poly_length: usize,
    /// cipher modulus minus one, refers to **Q-1**.
    pub cipher_modulus_minus_one: T,
    /// The modulus, refers to **Q** in the paper.
    pub cipher_modulus: M,
    /// The distribution type of the secret key.
    pub secret_key_distr: SecretKeyDistr,
    /// The noise's distribution.
    pub noise_distribution: DiscreteGaussian<T>,
    /// Decompose basis for `Q`.
    pub basis: ApproxSignedBasis<T>,
}

impl<T, M> RlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the poly length of this [`RlevParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the cipher modulus minus one of this [`RlevParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.cipher_modulus_minus_one
    }

    /// Returns the cipher modulus of this [`RlevParameters<T, M>`].
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the secret key type of this [`RlevParameters<T, M>`].
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_distr
    }

    /// Returns the noise standard deviation of this [`RlevParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_distribution.standard_deviation()
    }

    /// Returns a reference to the noise distribution of this [`RlevParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32, min_sigma: f64) -> DiscreteGaussian<T> {
        let noise_standard_deviation = self.noise_standard_deviation();
        let var = noise_standard_deviation * noise_standard_deviation;
        let sigma = (var / count as f64).sqrt().max(min_sigma);
        DiscreteGaussian::new(sigma, self.cipher_modulus_minus_one).unwrap()
    }

    /// Returns a reference to the basis of this [`RlevParameters<T, M>`].
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }
}

/// Rgsw Parameters.
pub type RgswParameters<ValueT, ModulusT> = RlevParameters<ValueT, ModulusT>;
