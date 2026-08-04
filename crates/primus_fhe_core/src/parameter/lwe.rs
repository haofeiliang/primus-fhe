use primus_decompose::primitive::ApproxSignedBasis;
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{LweSecretKeyType, PlaintextCodec};

/// Parameters controlling an LWE key-switching key.
///
/// The input and output ciphertext moduli are supplied by the corresponding
/// [`LweParameters`] at key generation or evaluation time. Keeping them out of
/// this type avoids cloning complete LWE parameter sets.
#[derive(Debug, Clone)]
pub struct LweKeySwitchingParameters<T: FheUint> {
    input_dimension: usize,
    output_dimension: usize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> LweKeySwitchingParameters<T> {
    /// Creates LWE key-switching parameters.
    ///
    /// # Panics
    ///
    /// Panics if either LWE dimension is zero.
    pub fn new(
        input_dimension: usize,
        output_dimension: usize,
        basis: ApproxSignedBasis<T>,
    ) -> Self {
        assert!(input_dimension > 0, "input LWE dimension must be non-zero");
        assert!(
            output_dimension > 0,
            "output LWE dimension must be non-zero"
        );
        Self {
            input_dimension,
            output_dimension,
            basis,
        }
    }

    /// Returns the dimension of ciphertexts before key switching.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the dimension of ciphertexts after key switching.
    #[inline]
    pub fn output_dimension(&self) -> usize {
        self.output_dimension
    }

    /// Returns the decomposition basis used by key switching.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the decomposition length.
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.basis.decompose_length()
    }
}

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
    /// **LWE** cipher modulus, refers to **q** in the paper.
    cipher_modulus: M,
    /// **LWE** cipher modulus minus one, refers to **q-1** in the paper.
    cipher_modulus_minus_one: T,
    cipher_modulus_uniform_distr: Uniform<T>,
    plaintext_codec: PlaintextCodec<T>,
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
        let plaintext_codec =
            PlaintextCodec::new(plain_modulus_value, cipher_modulus.explicit_value());

        Self {
            dimension,
            plain_modulus_value,
            cipher_modulus,
            cipher_modulus_minus_one,
            cipher_modulus_uniform_distr,
            plaintext_codec,
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
    pub fn plaintext_codec(&self) -> &PlaintextCodec<T> {
        &self.plaintext_codec
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
