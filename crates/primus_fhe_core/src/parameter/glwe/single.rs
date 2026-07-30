//! Single-modulus GLWE / GLev / GGSW parameters.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{PlaintextCodec, RingSecretKeyType};

/// Pre-computed size constants for a single-modulus GLWE ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlweCommonSize {
    dimension: usize,
    poly_length: usize,
    glwe_mid: usize,
    glwe_len: usize,
}

impl GlweCommonSize {
    /// Creates GLWE size constants for dimension `k` and polynomial length `N`.
    pub fn new(dimension: usize, poly_length: usize) -> Self {
        assert!(dimension > 0, "GLWE dimension must be non-zero");
        assert!(
            poly_length.is_power_of_two() && poly_length >= 2,
            "GLWE polynomial length must be a power of two greater than one"
        );

        let component_count = dimension
            .checked_add(1)
            .expect("GLWE component count overflow");
        let glwe_mid = dimension
            .checked_mul(poly_length)
            .expect("GLWE mask length overflow");
        let glwe_len = component_count
            .checked_mul(poly_length)
            .expect("GLWE ciphertext length overflow");
        Self {
            dimension,
            poly_length,
            glwe_mid,
            glwe_len,
        }
    }

    /// Returns the GLWE dimension `k`.
    #[inline]
    pub fn dimension(self) -> usize {
        self.dimension
    }

    /// Returns the polynomial length `N`.
    #[inline]
    pub fn poly_length(self) -> usize {
        self.poly_length
    }

    /// Returns the coefficient/NTT mask length `kN`.
    #[inline]
    pub fn glwe_mid(self) -> usize {
        self.glwe_mid
    }

    /// Returns the coefficient/NTT GLWE ciphertext length `(k + 1)N`.
    #[inline]
    pub fn glwe_len(self) -> usize {
        self.glwe_len
    }

    /// Returns the coefficient-domain secret-key length `kN`.
    #[inline]
    pub fn secret_key_len(self) -> usize {
        self.glwe_mid
    }

    /// Returns the Fourier mask length `kN/2`.
    #[inline]
    pub fn fourier_glwe_mid(self) -> usize {
        self.glwe_mid / 2
    }

    /// Returns the Fourier GLWE ciphertext length `(k + 1)N/2`.
    #[inline]
    pub fn fourier_glwe_len(self) -> usize {
        self.glwe_len / 2
    }
}

/// Pre-computed size constants for single-modulus GLev and GGSW ciphertexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlevCommonSize {
    glwe_common_size: GlweCommonSize,
    decompose_length: usize,
    glev_len: usize,
    ggsw_len: usize,
}

impl GlevCommonSize {
    /// Creates GLev/GGSW size constants from GLWE sizes and decomposition length.
    pub fn new(glwe_common_size: GlweCommonSize, decompose_length: usize) -> Self {
        assert!(
            decompose_length > 0,
            "GLev decomposition length must be non-zero"
        );

        let component_count = glwe_common_size
            .dimension()
            .checked_add(1)
            .expect("GGSW row count overflow");
        let glev_len = decompose_length
            .checked_mul(glwe_common_size.glwe_len())
            .expect("GLev ciphertext length overflow");
        let ggsw_len = component_count
            .checked_mul(glev_len)
            .expect("GGSW ciphertext length overflow");
        Self {
            glwe_common_size,
            decompose_length,
            glev_len,
            ggsw_len,
        }
    }

    /// Returns the underlying GLWE size constants.
    #[inline]
    pub fn glwe_common_size(self) -> GlweCommonSize {
        self.glwe_common_size
    }

    /// Returns the GLWE dimension `k`.
    #[inline]
    pub fn dimension(self) -> usize {
        self.glwe_common_size.dimension()
    }

    /// Returns the polynomial length `N`.
    #[inline]
    pub fn poly_length(self) -> usize {
        self.glwe_common_size.poly_length()
    }

    /// Returns the coefficient/NTT mask length `kN`.
    #[inline]
    pub fn glwe_mid(self) -> usize {
        self.glwe_common_size.glwe_mid()
    }

    /// Returns the coefficient/NTT GLWE ciphertext length.
    #[inline]
    pub fn glwe_len(self) -> usize {
        self.glwe_common_size.glwe_len()
    }

    /// Returns the coefficient-domain secret-key length `kN`.
    #[inline]
    pub fn secret_key_len(self) -> usize {
        self.glwe_common_size.secret_key_len()
    }

    /// Returns the Fourier mask length `kN/2`.
    #[inline]
    pub fn fourier_glwe_mid(self) -> usize {
        self.glwe_common_size.fourier_glwe_mid()
    }

    /// Returns the Fourier GLWE ciphertext length.
    #[inline]
    pub fn fourier_glwe_len(self) -> usize {
        self.glwe_common_size.fourier_glwe_len()
    }

    /// Returns the decomposition length.
    #[inline]
    pub fn decompose_length(self) -> usize {
        self.decompose_length
    }

    /// Returns the coefficient/NTT GLev ciphertext length.
    #[inline]
    pub fn glev_len(self) -> usize {
        self.glev_len
    }

    /// Returns the coefficient/NTT GGSW ciphertext length.
    #[inline]
    pub fn ggsw_len(self) -> usize {
        self.ggsw_len
    }

    /// Returns the Fourier GLev ciphertext length.
    #[inline]
    pub fn fourier_glev_len(self) -> usize {
        self.glev_len / 2
    }

    /// Returns the Fourier GGSW ciphertext length.
    #[inline]
    pub fn fourier_ggsw_len(self) -> usize {
        self.ggsw_len / 2
    }
}

/// GLWE encryption parameters shared by ordinary and gadget ciphertexts.
///
/// Ciphertext sizes and plaintext encoding intentionally live in their
/// respective outer parameter types.
#[derive(Clone)]
pub struct GlweParametersInner<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// **RLWE** cipher modulus minus one, refers to **Q-1**.
    cipher_modulus_minus_one: T,
    /// The modulus, refers to **Q** in the paper.
    cipher_modulus: M,
    cipher_modulus_uniform_distr: Uniform<T>,
    /// The distribution type of the secret key.
    secret_key_type: RingSecretKeyType,
    secret_key_distribution: Option<DiscreteGaussian<T>>,
    /// The noise's distribution.
    noise_distribution: DiscreteGaussian<T>,
}

impl<T, M> GlweParametersInner<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates GLWE encryption and secret-key parameters without ciphertext
    /// sizes or plaintext encoding.
    pub fn new(
        cipher_modulus: M,
        secret_key_type: RingSecretKeyType,
        noise_standard_deviation: f64,
    ) -> Self {
        let cipher_modulus_minus_one = cipher_modulus.minus_one();

        let noise_distribution =
            DiscreteGaussian::new(noise_standard_deviation, cipher_modulus_minus_one).unwrap();

        let cipher_modulus_uniform_distr = cipher_modulus.uniform_distribution();
        let secret_key_distribution =
            if let RingSecretKeyType::Gaussian(standard_deviation) = secret_key_type {
                Some(DiscreteGaussian::new(standard_deviation, cipher_modulus_minus_one).unwrap())
            } else {
                None
            };

        Self {
            cipher_modulus_minus_one,
            cipher_modulus,
            cipher_modulus_uniform_distr,
            secret_key_type,
            secret_key_distribution,
            noise_distribution,
        }
    }

    /// Returns the cipher modulus.
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.cipher_modulus
    }

    /// Returns the representable cipher modulus value, when one exists.
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
    pub fn secret_key_type(&self) -> RingSecretKeyType {
        self.secret_key_type
    }

    /// Returns the Gaussian secret-key distribution, when configured.
    #[inline]
    pub fn secret_key_distribution(&self) -> Option<&DiscreteGaussian<T>> {
        self.secret_key_distribution.as_ref()
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        &self.noise_distribution
    }

    /// Returns a noise distribution whose variance is divided by `count`.
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32, min_sigma: f64) -> DiscreteGaussian<T> {
        let noise_standard_deviation = self.noise_distribution.standard_deviation();
        let var = noise_standard_deviation * noise_standard_deviation;
        let sigma = (var / count as f64).sqrt().max(min_sigma);
        DiscreteGaussian::new(sigma, self.cipher_modulus_minus_one).unwrap()
    }
}

/// GLWE parameters including ciphertext sizes and plaintext encoding.
#[derive(Clone)]
pub struct GlweParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    common_size: GlweCommonSize,
    inner: GlweParametersInner<T, M>,
    plaintext_codec: PlaintextCodec<T>,
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
        let common_size = GlweCommonSize::new(dimension, poly_length);
        let cipher_modulus_value = cipher_modulus.explicit_value();
        let plaintext_codec = PlaintextCodec::new(plain_modulus_value, cipher_modulus_value);

        let inner =
            GlweParametersInner::new(cipher_modulus, secret_key_type, noise_standard_deviation);

        Self {
            common_size,
            inner,
            plaintext_codec,
        }
    }

    /// Returns the parameters shared by GLWE and its gadget ciphertexts.
    #[inline]
    pub fn inner(&self) -> &GlweParametersInner<T, M> {
        &self.inner
    }

    /// Returns the dimension of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.common_size.dimension()
    }

    /// Returns the poly length of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.common_size.poly_length()
    }

    /// Returns the pre-computed GLWE size constants.
    #[inline]
    pub fn common_size(&self) -> GlweCommonSize {
        self.common_size
    }

    /// Returns the coefficient/NTT mask length `kN`.
    #[inline]
    pub fn glwe_mid(&self) -> usize {
        self.common_size.glwe_mid()
    }

    /// Returns the coefficient/NTT GLWE ciphertext length `(k + 1)N`.
    #[inline]
    pub fn glwe_len(&self) -> usize {
        self.common_size.glwe_len()
    }

    /// Returns the coefficient-domain secret-key length `kN`.
    #[inline]
    pub fn secret_key_len(&self) -> usize {
        self.common_size.secret_key_len()
    }

    /// Returns the Fourier mask length `kN/2`.
    #[inline]
    pub fn fourier_glwe_mid(&self) -> usize {
        self.common_size.fourier_glwe_mid()
    }

    /// Returns the Fourier GLWE ciphertext length `(k + 1)N/2`.
    #[inline]
    pub fn fourier_glwe_len(&self) -> usize {
        self.common_size.fourier_glwe_len()
    }

    /// Returns the plain modulus value of this [`GlweParameters<T, M>`].
    pub fn plain_modulus_value(&self) -> T {
        self.plaintext_codec.t()
    }

    /// Returns the preselected plaintext codec strategy.
    #[inline]
    pub fn plaintext_codec(&self) -> &PlaintextCodec<T> {
        &self.plaintext_codec
    }

    /// Returns the cipher modulus of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus(&self) -> M {
        self.inner.cipher_modulus()
    }

    /// Returns the cipher modulus of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus_value(&self) -> T {
        self.inner
            .cipher_modulus_value()
            .expect("native cipher modulus has no representable modulus value")
    }

    /// Returns the cipher modulus minus one of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.inner.cipher_modulus_minus_one()
    }

    /// Returns the cipher modulus uniform distr of this [`GlweParameters<T, M>`].
    pub fn cipher_modulus_uniform_distr(&self) -> Uniform<T> {
        self.inner.cipher_modulus_uniform_distr()
    }

    /// Returns the secret key type of this [`GlweParameters<T, M>`].
    pub fn secret_key_type(&self) -> RingSecretKeyType {
        self.inner.secret_key_type()
    }

    /// Returns the secret key distribution of this [`GlweParameters<T, M>`].
    pub fn secret_key_distribution(&self) -> Option<&DiscreteGaussian<T>> {
        self.inner.secret_key_distribution()
    }

    /// Returns a reference to the noise distribution of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        self.inner.noise_distribution()
    }

    /// Returns the noise distribution.
    #[inline]
    pub fn noise_distribution_div_count(&self, count: u32, min_sigma: f64) -> DiscreteGaussian<T> {
        self.inner.noise_distribution_div_count(count, min_sigma)
    }
}

/// Glev Parameters.
#[derive(Clone)]
pub struct GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    common_size: GlevCommonSize,
    inner: GlweParametersInner<T, M>,
    /// Decompose basis for `Q`.
    basis: ApproxSignedBasis<T>,
}

/// Parameters for switching a GLWE ciphertext from an input secret key to an
/// output secret key.
///
/// Each input secret polynomial is encrypted as one GLev ciphertext under the
/// output key. Consequently, the output GLWE layout, encryption noise and
/// decomposition basis are all described by [`GlevParameters`].
#[derive(Clone)]
pub struct GlweKeySwitchingParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    input_dimension: usize,
    output: GlevParameters<T, M>,
}

impl<T, M> GlweKeySwitchingParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates GLWE key-switching parameters.
    ///
    /// `input_dimension` is the number of mask polynomials in the input GLWE
    /// key. The output dimension and polynomial length are taken from
    /// `output`.
    #[inline]
    pub fn new(input_dimension: usize, output: GlevParameters<T, M>) -> Self {
        assert!(input_dimension > 0, "input GLWE dimension must be non-zero");
        Self {
            input_dimension,
            output,
        }
    }

    /// Returns the input GLWE dimension.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the output GLWE dimension.
    #[inline]
    pub fn output_dimension(&self) -> usize {
        self.output.dimension()
    }

    /// Returns the common polynomial length of the input and output keys.
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.output.poly_length()
    }

    /// Returns the GLev parameters used for every key-switching entry.
    #[inline]
    pub fn output(&self) -> &GlevParameters<T, M> {
        &self.output
    }

    /// Returns the coefficient/NTT-domain key length.
    #[inline]
    pub fn key_len(&self) -> usize {
        self.input_dimension
            .checked_mul(self.output.glev_len())
            .expect("GLWE key-switching key length overflow")
    }

    /// Returns the Fourier-domain key length.
    #[inline]
    pub fn fourier_key_len(&self) -> usize {
        self.input_dimension
            .checked_mul(self.output.fourier_glev_len())
            .expect("Fourier GLWE key-switching key length overflow")
    }
}

impl<T, M> GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Creates a new [`GlevParameters<T, M>`].
    #[inline]
    pub fn new(
        glwe_common_size: GlweCommonSize,
        inner: GlweParametersInner<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Self {
        let common_size = GlevCommonSize::new(glwe_common_size, basis.decompose_length());
        Self {
            common_size,
            inner,
            basis,
        }
    }

    /// Creates GLev/GGSW parameters from matching GLWE parameters.
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Self {
        Self::new(
            glwe_params.common_size(),
            glwe_params.inner().clone(),
            basis,
        )
    }

    /// Returns the underlying GLWE size constants.
    #[inline]
    pub fn glwe_common_size(&self) -> GlweCommonSize {
        self.common_size.glwe_common_size()
    }

    /// Returns the parameters shared by GLWE and its gadget ciphertexts.
    #[inline]
    pub fn inner(&self) -> &GlweParametersInner<T, M> {
        &self.inner
    }

    /// Returns the pre-computed GLev/GGSW size constants.
    #[inline]
    pub fn common_size(&self) -> GlevCommonSize {
        self.common_size
    }

    /// Returns the dimension of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.common_size.dimension()
    }

    /// Returns the poly length of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.common_size.poly_length()
    }

    /// Returns the cipher modulus minus one of this [`GlevParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> T {
        self.inner.cipher_modulus_minus_one()
    }

    /// Returns the modulus of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> M {
        self.inner.cipher_modulus()
    }

    /// Returns the secret key type of this [`GlevParameters<T, M>`].
    pub fn secret_key_type(&self) -> RingSecretKeyType {
        self.inner.secret_key_type()
    }

    /// Returns a reference to the noise distribution of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &DiscreteGaussian<T> {
        self.inner.noise_distribution()
    }

    /// Returns the noise standard deviation of this [`GlevParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.inner.noise_distribution().standard_deviation()
    }

    /// Returns a reference to the basis of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the decomposition length.
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.common_size.decompose_length()
    }

    /// Returns the coefficient/NTT mask length `kN`.
    #[inline]
    pub fn glwe_mid(&self) -> usize {
        self.common_size.glwe_mid()
    }

    /// Returns the number of values in one coefficient/NTT-domain GLWE ciphertext.
    #[inline]
    pub fn glwe_len(&self) -> usize {
        self.common_size.glwe_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GLev ciphertext.
    #[inline]
    pub fn glev_len(&self) -> usize {
        self.common_size.glev_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GGSW ciphertext.
    #[inline]
    pub fn ggsw_len(&self) -> usize {
        self.common_size.ggsw_len()
    }

    /// Returns the number of complex values in one Fourier-domain GLWE ciphertext.
    #[inline]
    pub fn fourier_glwe_len(&self) -> usize {
        self.common_size.fourier_glwe_len()
    }

    /// Returns the Fourier mask length `kN/2`.
    #[inline]
    pub fn fourier_glwe_mid(&self) -> usize {
        self.common_size.fourier_glwe_mid()
    }

    /// Returns the number of complex values in one Fourier-domain GLev ciphertext.
    #[inline]
    pub fn fourier_glev_len(&self) -> usize {
        self.common_size.fourier_glev_len()
    }

    /// Returns the number of complex values in one Fourier-domain GGSW ciphertext.
    #[inline]
    pub fn fourier_ggsw_len(&self) -> usize {
        self.common_size.fourier_ggsw_len()
    }
}

/// Ggsw Parameters.
pub type GgswParameters<T, M> = GlevParameters<T, M>;
