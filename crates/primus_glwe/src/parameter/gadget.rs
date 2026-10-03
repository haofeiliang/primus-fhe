//! GLev/GGSW layouts and signed-decomposition basis.

use primus_decompose::{
    DecompositionBaseLog, DecompositionLevelCount, primitive::ApproxSignedBasis,
};
use primus_distr::DiscreteGaussian;
use primus_integer::FheUint;
use primus_lattice::{GadgetSize, GlweDimension, GlweSize};
use primus_poly::PolyLength;
use primus_reduce::RingContext;
use std::sync::Arc;

use super::{GlevParameterError, GlweParameters, GlweParametersInner};
use crate::SecretKeyDistr;

/// GLWE parameters and decomposition basis shared by GLev and GGSW operations.
/// Owns the gadget layout and decomposition basis, and shares immutable modulus
/// and sampling state through `Arc`. No plaintext codec is needed. Ordinary and
/// gadget parameters may share that state when their encryption roles agree.
#[derive(Clone)]
pub struct GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    size: GadgetSize,
    pub(super) inner: Arc<GlweParametersInner<T, M>>,
    /// Decompose basis for `Q`.
    basis: ApproxSignedBasis<T>,
}

impl<T, M> GlevParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Binds a GLWE layout and prepared sampling state to a gadget basis.
    ///
    /// Takes ownership of the shared state and basis without rebuilding sampler
    /// tables or basis precomputation. The noise in `inner` encrypts each gadget
    /// row; callers choose it for the intended evaluation-key role.
    ///
    /// # Errors
    ///
    /// Rejects a fixed secret weight exceeding the complete `kN` key length,
    /// a basis modulus mismatch (including native versus explicit), or gadget
    /// layout overflow. Modulus support and noise were checked by `inner`.
    pub fn try_from_parts(
        glwe_size: GlweSize,
        inner: Arc<GlweParametersInner<T, M>>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, GlevParameterError> {
        if basis.modulus() != inner.cipher_modulus_value() {
            return Err(GlevParameterError::BasisModulusMismatch);
        }
        inner
            .secret_key_sampler()
            .validate_length(glwe_size.mask_len())?;
        Ok(Self {
            size: GadgetSize::try_new(glwe_size, basis.decompose_length())?,
            inner,
            basis,
        })
    }

    /// Reuses a precomputed decomposition basis with matching GLWE parameters.
    ///
    /// Takes ownership of the basis, preserving its levels and precomputation,
    /// and shares the source parameters' prepared samplers without copying them.
    /// Both native (`None`) and explicit modulus representations must match.
    ///
    /// # Errors
    ///
    /// Returns an error on a basis modulus mismatch or gadget layout overflow.
    pub fn try_with_basis(
        glwe_params: &GlweParameters<T, M>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<Self, GlevParameterError> {
        Self::try_from_parts(glwe_params.size(), Arc::clone(&glwe_params.inner), basis)
    }

    /// Creates GLev/GGSW parameters from matching GLWE parameters.
    ///
    /// # Panics
    ///
    /// Panics on invalid basis parameters or gadget layout overflow.
    #[must_use]
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        log_basis: DecompositionBaseLog,
        reverse_length: Option<DecompositionLevelCount>,
    ) -> Self {
        Self::try_with_glwe_params(glwe_params, log_basis, reverse_length)
            .unwrap_or_else(|message| panic!("failed to construct GLev parameters: {message}"))
    }

    /// Tries to create GLev/GGSW parameters and their decomposition basis from
    /// one GLWE modulus domain.
    ///
    /// # Errors
    ///
    /// Returns an error on invalid basis parameters or gadget layout overflow.
    #[inline]
    pub fn try_with_glwe_params(
        glwe_params: &GlweParameters<T, M>,
        log_basis: DecompositionBaseLog,
        reverse_length: Option<DecompositionLevelCount>,
    ) -> Result<Self, GlevParameterError> {
        let basis = ApproxSignedBasis::try_new(
            glwe_params.cipher_modulus_value(),
            log_basis,
            reverse_length,
        )?;
        Self::try_with_basis(glwe_params, basis)
    }

    /// Returns the parameters shared by GLWE and its gadget ciphertexts.
    #[inline]
    pub fn inner(&self) -> &GlweParametersInner<T, M> {
        self.inner.as_ref()
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
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> GlweDimension {
        self.size.glwe_size().dimension()
    }

    /// Returns the poly length of this [`GlevParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
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
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.inner.secret_key_distr()
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
    #[must_use]
    #[inline]
    pub fn decompose_length(&self) -> DecompositionLevelCount {
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
