//! Single-modulus GLWE / GLev / GGSW parameters.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_distr::DiscreteGaussian;
use primus_factor::{FactorBase, ShoupFactor};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{PlaintextCodec, RingSecretKeyType};

/// Glwe Parameters.
#[derive(Clone)]
pub struct GlweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// The dimension, refers to **k** in the paper.
    dimension: usize,
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
    delta_factor: Option<ShoupFactor<T>>,
    /// The distribution type of the secret key.
    secret_key_type: RingSecretKeyType,
    secret_key_distribution: Option<DiscreteGaussian<T>>,
    /// The noise's distribution.
    noise_distribution: DiscreteGaussian<T>,
}

impl<T, M> GlweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a new [`GlweParameters<T, M>`].
    pub fn new(
        dimension: usize,
        poly_length: usize,
        plain_modulus_value: T,
        cipher_modulus: M,
        secret_key_type: RingSecretKeyType,
        noise_standard_deviation: f64,
    ) -> Self {
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one).unwrap();

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        let cipher_modulus_value = cipher_modulus.value();
        let plaintext_codec = PlaintextCodec::new(plain_modulus_value, cipher_modulus_value);

        let delta = match cipher_modulus_value {
            Some(q) => {
                let (mut delta, rem) = q.div_rem(plain_modulus_value);
                if rem > (plain_modulus_value - T::ONE) / T::TWO {
                    delta += T::ONE;
                }
                delta
            }
            None => {
                // round(2^BITS / t), represented without materializing 2^BITS
                T::div_wide(plain_modulus_value >> 1u32, T::ONE, plain_modulus_value)
            }
        };

        let delta_factor = cipher_modulus_value.map(|q| ShoupFactor::new(delta, q));

        let secret_key_distribution =
            if let RingSecretKeyType::Gaussian(standard_deviation) = secret_key_type {
                Some(DiscreteGaussian::new(standard_deviation, cipher_modulus_minus_one).unwrap())
            } else {
                None
            };

        Self {
            dimension,
            poly_length,
            plain_modulus_value,
            plaintext_codec,
            cipher_modulus_minus_one,
            cipher_modulus,
            cipher_modulus_uniform_distr,
            delta,
            delta_factor,
            secret_key_type,
            secret_key_distribution,
            noise_distribution,
        }
    }

    /// Returns the dimension of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.dimension
    }

    /// Returns the poly length of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.poly_length
    }

    /// Returns the plain modulus value of this [`GlweParameters<T, M>`].
    pub fn plain_modulus_value(&self) -> T {
        self.plain_modulus_value
    }

    /// Returns the preselected plaintext codec strategy.
    #[inline]
    pub fn plaintext_codec(&self) -> &PlaintextCodec<T> {
        &self.plaintext_codec
    }

    /// Returns the cipher modulus of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the cipher modulus of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus_value(&self) -> T {
        self.cipher_modulus
            .value()
            .expect("native cipher modulus has no representable modulus value")
    }

    /// Returns the cipher modulus minus one of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.cipher_modulus_minus_one
    }

    /// Returns the cipher modulus uniform distr of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.cipher_modulus_uniform_distr
    }

    /// Returns the delta of this [`GlweParameters<T, M>`].
    pub fn delta(&self) -> T {
        self.delta
    }

    /// Returns the delta factor of this [`GlweParameters<T, M>`].
    pub fn delta_factor(&self) -> ShoupFactor<T> {
        self.delta_factor
            .expect("Shoup delta factor is unavailable for the native cipher modulus")
    }

    /// Returns the secret key type of this [`GlweParameters<T, M>`].
    pub fn secret_key_type(&self) -> RingSecretKeyType {
        self.secret_key_type
    }

    /// Returns the secret key distribution of this [`GlweParameters<T, M>`].
    pub fn secret_key_distribution(&self) -> Option<&DiscreteGaussian<T>> {
        self.secret_key_distribution.as_ref()
    }

    /// Returns a reference to the noise distribution of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32, min_sigma: f64) -> DiscreteGaussian<T> {
        let noise_standard_deviation = self.noise_distribution.standard_deviation();
        let var = noise_standard_deviation * noise_standard_deviation;
        let sigma = (var / count as f64).sqrt().max(min_sigma);
        DiscreteGaussian::new(sigma, self.cipher_modulus_minus_one).unwrap()
    }
}

/// Glev Parameters.
#[derive(Clone)]
pub struct GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    glwe_params: GlweParameters<T, M>,
    /// Decompose basis for `Q`.
    basis: ApproxSignedBasis<T>,
}

impl<T, M> GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a new [`GlevParameters<T, M>`].
    #[inline]
    pub fn new(glwe_params: GlweParameters<T, M>, basis: ApproxSignedBasis<T>) -> Self {
        Self { glwe_params, basis }
    }

    /// Creates GLev/GGSW parameters from matching GLWE parameters.
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Self {
        Self::new(glwe_params.clone(), basis)
    }

    /// Returns the underlying GLWE parameters.
    #[inline]
    pub fn glwe_params(&self) -> &GlweParameters<T, M> {
        &self.glwe_params
    }

    /// Returns the dimension of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.glwe_params.dimension()
    }

    /// Returns the poly length of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.glwe_params.poly_length()
    }

    /// Returns the cipher modulus minus one of this [`GlevParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.glwe_params.cipher_modulus_minus_one()
    }

    /// Returns the modulus of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.glwe_params.cipher_modulus()
    }

    /// Returns the secret key type of this [`GlevParameters<T, M>`].
    pub fn secret_key_type(&self) -> RingSecretKeyType {
        self.glwe_params.secret_key_type()
    }

    /// Returns a reference to the noise distribution of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        self.glwe_params.noise_distribution()
    }

    /// Returns the noise standard deviation of this [`GlevParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.glwe_params.noise_distribution().standard_deviation()
    }

    /// Returns a reference to the basis of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the number of values in one coefficient/NTT-domain GLWE ciphertext.
    #[inline]
    pub fn glwe_len(&self) -> usize {
        (self.dimension() + 1) * self.poly_length()
    }

    /// Returns the number of values in one coefficient/NTT-domain GLev ciphertext.
    #[inline]
    pub fn glev_len(&self) -> usize {
        self.basis.decompose_length() * self.glwe_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GGSW ciphertext.
    #[inline]
    pub fn ggsw_len(&self) -> usize {
        (self.dimension() + 1) * self.glev_len()
    }

    /// Returns the number of complex values in one Fourier-domain GLWE ciphertext.
    #[inline]
    pub fn fourier_glwe_len(&self) -> usize {
        (self.dimension() + 1) * (self.poly_length() / 2)
    }

    /// Returns the number of complex values in one Fourier-domain GLev ciphertext.
    #[inline]
    pub fn fourier_glev_len(&self) -> usize {
        self.basis.decompose_length() * self.fourier_glwe_len()
    }

    /// Returns the number of complex values in one Fourier-domain GGSW ciphertext.
    #[inline]
    pub fn fourier_ggsw_len(&self) -> usize {
        (self.dimension() + 1) * self.fourier_glev_len()
    }
}

/// Ggsw Parameters.
pub type GgswParameters<T, M> = GlevParameters<T, M>;
