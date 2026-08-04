//! Single-modulus GLWE / GLev / GGSW parameters.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, GlweSize};
use primus_reduce::RingContext;
use rand::distr::Uniform;

use crate::{PlaintextCodec, RingSecretKeyType};

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
    /// The modulus, refers to **Q** in the paper.
    cipher_modulus: M,
    /// **RLWE** cipher modulus minus one, refers to **Q-1**.
    cipher_modulus_minus_one: T,
    cipher_modulus_uniform_distr: Uniform<T>,
    /// The distribution type of the secret key.
    secret_key_type: RingSecretKeyType,
    secret_key_distribution: Option<DiscreteGaussian<T>>,
    /// The noise's distribution.
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
            && self.secret_key_type == other.secret_key_type
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
            cipher_modulus,
            cipher_modulus_minus_one,
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
    size: GlweSize,
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
        let size = GlweSize::new(dimension, poly_length);
        let cipher_modulus_value = cipher_modulus.explicit_value();
        let plaintext_codec = PlaintextCodec::new(plain_modulus_value, cipher_modulus_value);

        let inner =
            GlweParametersInner::new(cipher_modulus, secret_key_type, noise_standard_deviation);

        Self {
            size,
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
        self.size.dimension()
    }

    /// Returns the poly length of this [`GlweParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.size.poly_length()
    }

    /// Returns the pre-computed GLWE size constants.
    #[inline]
    pub fn size(&self) -> GlweSize {
        self.size
    }

    /// Returns the coefficient/NTT mask length `kN`.
    #[inline]
    pub fn glwe_mid(&self) -> usize {
        self.size.mask_len()
    }

    /// Returns the coefficient/NTT GLWE ciphertext length `(k + 1)N`.
    #[inline]
    pub fn glwe_len(&self) -> usize {
        self.size.glwe_len()
    }

    /// Returns the coefficient-domain secret-key length `kN`.
    #[inline]
    pub fn secret_key_len(&self) -> usize {
        self.size.mask_len()
    }

    /// Returns the Fourier mask length `kN/2`.
    #[inline]
    pub fn fourier_glwe_mid(&self) -> usize {
        self.size.fourier_mask_len()
    }

    /// Returns the Fourier GLWE ciphertext length `(k + 1)N/2`.
    #[inline]
    pub fn fourier_glwe_len(&self) -> usize {
        self.size.fourier_glwe_len()
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
    size: GadgetSize,
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

    /// Returns the input GLWE layout.
    #[inline]
    pub fn input_size(&self) -> GlweSize {
        GlweSize::new(self.input_dimension, self.poly_length())
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

    /// Returns the output gadget layout.
    #[inline]
    pub fn output_size(&self) -> GadgetSize {
        self.output.size()
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
    pub(crate) fn from_parts(
        size: GlweSize,
        inner: GlweParametersInner<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Self {
        assert_eq!(
            basis.modulus(),
            inner.cipher_modulus_value(),
            "GLev decomposition basis must match the GLWE ciphertext modulus"
        );
        Self {
            size: GadgetSize::new(size, basis.decompose_length()),
            inner,
            basis,
        }
    }

    /// Creates GLev/GGSW parameters from matching GLWE parameters.
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        log_basis: u32,
        reverse_length: Option<usize>,
    ) -> Self {
        Self::try_with_glwe_params(glwe_params, log_basis, reverse_length)
            .unwrap_or_else(|message| panic!("failed to construct GLev parameters: {message}"))
    }

    /// Tries to create GLev/GGSW parameters and their decomposition basis from
    /// one GLWE modulus domain.
    #[inline]
    pub fn try_with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        log_basis: u32,
        reverse_length: Option<usize>,
    ) -> Result<Self, primus_decompose::ApproxSignedBasisError> {
        let basis = ApproxSignedBasis::try_new(
            glwe_params.inner().cipher_modulus_value(),
            log_basis,
            reverse_length,
        )?;
        Ok(Self::from_parts(
            glwe_params.size(),
            glwe_params.inner().clone(),
            basis,
        ))
    }

    /// Returns the parameters shared by GLWE and its gadget ciphertexts.
    #[inline]
    pub fn inner(&self) -> &GlweParametersInner<T, M> {
        &self.inner
    }

    /// Returns the pre-computed GLev/GGSW size constants.
    #[inline]
    pub fn size(&self) -> GadgetSize {
        self.size
    }

    /// Returns the underlying GLWE size constants.
    #[inline]
    pub fn glwe_size(&self) -> GlweSize {
        self.size.glwe_size()
    }

    /// Returns the dimension of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.size.glwe_size().dimension()
    }

    /// Returns the poly length of this [`GlevParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.size.glwe_size().poly_length()
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
        self.size.decompose_length()
    }

    /// Returns the coefficient/NTT mask length `kN`.
    #[inline]
    pub fn glwe_mid(&self) -> usize {
        self.size.glwe_size().mask_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GLWE ciphertext.
    #[inline]
    pub fn glwe_len(&self) -> usize {
        self.size.glwe_size().glwe_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GLev ciphertext.
    #[inline]
    pub fn glev_len(&self) -> usize {
        self.size.glev_len()
    }

    /// Returns the number of values in one coefficient/NTT-domain GGSW ciphertext.
    #[inline]
    pub fn ggsw_len(&self) -> usize {
        self.size.ggsw_len()
    }

    /// Returns the number of complex values in one Fourier-domain GLWE ciphertext.
    #[inline]
    pub fn fourier_glwe_len(&self) -> usize {
        self.size.glwe_size().fourier_glwe_len()
    }

    /// Returns the Fourier mask length `kN/2`.
    #[inline]
    pub fn fourier_glwe_mid(&self) -> usize {
        self.size.glwe_size().fourier_mask_len()
    }

    /// Returns the number of complex values in one Fourier-domain GLev ciphertext.
    #[inline]
    pub fn fourier_glev_len(&self) -> usize {
        self.size.fourier_glev_len()
    }

    /// Returns the number of complex values in one Fourier-domain GGSW ciphertext.
    #[inline]
    pub fn fourier_ggsw_len(&self) -> usize {
        self.size.fourier_ggsw_len()
    }
}

/// Ggsw Parameters.
pub type GgswParameters<T, M> = GlevParameters<T, M>;
