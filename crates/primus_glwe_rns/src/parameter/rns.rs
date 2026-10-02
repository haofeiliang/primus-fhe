//! RNS (Residue Number System) multi-modulus GLWE / GLev / GGSW parameters.

use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_distr::{SecretKeySampler, SignedDiscreteGaussian};
use primus_encoding::PlaintextEmbedding;
use primus_factor::ShoupFactor;
use primus_integer::{BigUint, FheUint};
use primus_lattice::GlweDimension;
use primus_lattice::{GlweSize, RnsGadgetSize, RnsGlweSize};
use primus_poly::PolyLength;
use primus_reduce::FieldContext;
use primus_rns::{RNSBase, ResidueFactors, Residues};
use rand::distr::Uniform;
use std::sync::Arc;

use crate::{BfvRnsCodec, SecretKeyDistr};

use super::{CrtGlevParametersError, CrtGlweParametersError};

/// Layout and sampling state shared by ordinary and gadget parameters.
///
/// Base-dependent caches follow the immutable ordered base owned by each outer
/// type: the ordinary codec or the gadget base. No second RNSBase is stored here.
/// Arc sharing retains the same prepared Gaussian tables and secret sampler when
/// gadget parameters are derived, instead of cloning those precomputations.
struct CrtGlweParametersInner<T: FheUint> {
    size: RnsGlweSize,
    cipher_modulus_minus_one: BigUint<Vec<T>>,
    cipher_moduli_minus_one: Vec<T>,
    cipher_moduli_uniform_distr: Vec<Uniform<T>>,
    secret_key_sampler: SecretKeySampler<T>,
    noise_distribution: SignedDiscreteGaussian<T::SignedInteger>,
}

impl<T: FheUint> CrtGlweParametersInner<T> {
    /// Prepares the complete kN secret and noise domains once at construction.
    /// The base is already valid and size has the same ordered modulus count.
    fn try_new<M: FieldContext<T>>(
        size: RnsGlweSize,
        base_q: &RNSBase<T, M>,
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, CrtGlweParametersError<T>> {
        let secret_key_sampler = SecretKeySampler::try_new(secret_key_distr)?;
        secret_key_sampler.validate_length(size.glwe_size().mask_len())?;
        let noise_distribution = SignedDiscreteGaussian::new(noise_standard_deviation)?;
        let maximum_magnitude = noise_distribution.maximum_magnitude();
        for modulus in base_q.moduli() {
            let modulus_minus_one = modulus.minus_one();
            secret_key_sampler.validate_modulus(modulus_minus_one)?;
            if u128::from(maximum_magnitude) > modulus_minus_one.as_into() {
                return Err(primus_distr::GaussianError::ModulusTooSmall {
                    maximum_magnitude,
                    modulus_minus_one: modulus_minus_one.as_into(),
                }
                .into());
            }
        }

        let mut cipher_modulus_minus_one = BigUint(base_q.moduli_product().0.to_vec());
        let borrow = cipher_modulus_minus_one.sub_value_assign(T::ONE);
        debug_assert!(!borrow);
        Ok(Self {
            size,
            cipher_modulus_minus_one,
            cipher_moduli_minus_one: base_q.moduli().iter().map(|q| q.minus_one()).collect(),
            cipher_moduli_uniform_distr: base_q
                .moduli()
                .iter()
                .map(|q| q.uniform_distribution())
                .collect(),
            secret_key_sampler,
            noise_distribution,
        })
    }
}

/// Ordinary CRT GLWE parameters with a BFV plaintext codec.
///
/// Construction checks layout, ordered RNS moduli, encoding, fixed secret
/// weights and the supported secret/noise magnitudes. It also establishes a
/// sufficient recovery bound for fresh private-key plaintext encryption under
/// either embedding. The immutable sampling state is reused by gadget parameters;
/// the codec and its scaling stay here.
#[derive(Clone)]
pub struct CrtGlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    inner: Arc<CrtGlweParametersInner<T>>,
    codec: BfvRnsCodec<T, M>,
    delta_mod_q: Vec<T>,
}

impl<T, M> CrtGlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a new [`CrtGlweParameters<T, M>`].
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_new`] rejects layout, RNS/encoding or sampling
    /// parameters, including fixed weights exceeding the complete kN key length
    /// or insufficient fresh private-key plaintext recovery margin.
    #[must_use]
    pub fn new(
        dimension: GlweDimension,
        poly_length: usize,
        plain_modulus: M,
        gamma_modulus: M,
        cipher_moduli: &[M],
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        Self::try_new(
            dimension,
            poly_length,
            plain_modulus,
            gamma_modulus,
            cipher_moduli,
            secret_key_distr,
            noise_standard_deviation,
        )
        .expect("invalid CRT GLWE parameters")
    }

    /// Creates a [`CrtGlweParameters<T, M>`] with checked layout, encoding and sampling.
    ///
    /// Fixed weights apply to all kN signed secret coefficients, not per polynomial
    /// or RNS limb. Every supported secret and noise magnitude must be strictly
    /// smaller than each ciphertext modulus. Noise deviation is in coefficient units.
    /// The truncated noise support must satisfy [`BfvRnsCodec::validate_noise_bound`]
    /// for unsigned lifting, which also covers centered lifting. This guarantees
    /// recovery for fresh private-key plaintext encryption; public-key and
    /// homomorphic-operation noise need their own bounds. No NTT table or security
    /// level is established here.
    ///
    /// # Correctness
    ///
    /// Encoding inherits [`BfvRnsCodec::try_new`]'s arithmetic-context requirements.
    ///
    /// # Errors
    ///
    /// Returns [`CrtGlweParametersError`] for invalid layout, RNS/encoding or
    /// secret/noise sampling parameters, preserving the underlying reason.
    pub fn try_new(
        dimension: GlweDimension,
        poly_length: usize,
        plain_modulus: M,
        gamma_modulus: M,
        cipher_moduli: &[M],
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Result<Self, CrtGlweParametersError<T>> {
        let poly_length = PolyLength::try_new(poly_length)
            .map_err(|_| primus_lattice::GlweSizeError::InvalidPolynomialLength)?;
        let glwe_size = GlweSize::try_new(dimension, poly_length)?;
        let base_q = RNSBase::new(cipher_moduli)?;
        let size = RnsGlweSize::try_new(glwe_size, base_q.moduli_count())?;
        let codec = BfvRnsCodec::try_new(plain_modulus, base_q, gamma_modulus)?;
        let inner = CrtGlweParametersInner::try_new(
            size,
            codec.base_q(),
            secret_key_distr,
            noise_standard_deviation,
        )?;
        // Every modulus already contains the signed support, so the magnitude
        // fits T. For private-key plaintext encryption it bounds the phase noise.
        let maximum_noise_magnitude = T::as_from(inner.noise_distribution.maximum_magnitude());
        codec.validate_noise_bound(maximum_noise_magnitude, PlaintextEmbedding::Unsigned)?;
        let inner = Arc::new(inner);
        let delta_mod_q = codec
            .delta_factor_mod_q()
            .iter()
            .map(|factor| factor.value())
            .collect();
        Ok(Self {
            inner,
            codec,
            delta_mod_q,
        })
    }

    /// Returns the dimension of this [`CrtGlweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> GlweDimension {
        self.inner.size.dimension()
    }

    /// Returns the poly length of this [`CrtGlweParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.inner.size.poly_length()
    }

    /// Returns the plain modulus value of this [`CrtGlweParameters<T, M>`].
    pub fn plain_modulus_value(&self) -> T {
        self.codec.t()
    }

    /// Returns a reference to the cipher modulus of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_modulus(&self) -> BigUint<&[T]> {
        self.codec.base_q().moduli_product()
    }

    /// Returns a reference to the modulus minus one of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> BigUint<&[T]> {
        self.inner.cipher_modulus_minus_one.view()
    }

    /// Returns a reference to the moduli of this [`CrtGlweParameters<T, M>`].
    #[inline]
    pub fn cipher_moduli(&self) -> &[M] {
        self.codec.base_q().moduli()
    }

    /// Returns a reference to the cipher moduli value of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_value(&self) -> &[T] {
        self.codec.moduli_values()
    }

    /// Returns a reference to the cipher moduli minus one of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_minus_one(&self) -> &[T] {
        &self.inner.cipher_moduli_minus_one
    }

    /// Returns the moduli count of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_count(&self) -> usize {
        self.codec.moduli_count()
    }

    /// Returns a reference to the cipher moduli uniform distr of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<T>] {
        &self.inner.cipher_moduli_uniform_distr
    }

    /// Returns the big uint value len of this [`CrtGlweParameters<T, M>`].
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.codec.base_q().big_uint_value_len()
    }

    /// Returns the secret key type of this [`CrtGlweParameters<T, M>`].
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.inner.secret_key_sampler.distr()
    }

    /// Returns shared precomputation for coefficient secret-key generation.
    #[must_use]
    #[inline]
    pub fn secret_key_sampler(&self) -> &SecretKeySampler<T> {
        &self.inner.secret_key_sampler
    }

    /// Returns a reference to the noise distribution of this [`CrtGlweParameters<T, M>`].
    pub fn noise_distribution(&self) -> &SignedDiscreteGaussian<T::SignedInteger> {
        &self.inner.noise_distribution
    }

    /// Returns the noise standard deviation of this [`CrtGlweParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.inner.noise_distribution.standard_deviation()
    }

    /// Returns a reference to the delta of this [`CrtGlweParameters<T, M>`].
    pub fn delta(&self) -> BigUint<&[T]> {
        self.codec.delta()
    }

    /// Returns a reference to the delta residues of this [`CrtGlweParameters<T, M>`].
    pub fn delta_mod_q(&self) -> &[T] {
        &self.delta_mod_q
    }

    /// Returns a reference to the delta residues of this [`CrtGlweParameters<T, M>`].
    pub fn delta_factor_mod_q(&self) -> ResidueFactors<&[ShoupFactor<T>]> {
        self.codec.delta_factor_mod_q()
    }

    /// Returns the ordered ciphertext RNS basis Q.
    pub fn base_q(&self) -> &RNSBase<T, M> {
        self.codec.base_q()
    }

    /// Returns the plaintext coefficient codec bound to this RNS basis.
    pub fn codec(&self) -> &BfvRnsCodec<T, M> {
        &self.codec
    }

    /// Returns the cached RNS GLWE layout.
    pub fn size(&self) -> RnsGlweSize {
        self.inner.size
    }

    /// Returns the limb length of one polynomial in big-integer representation.
    pub fn big_uint_poly_len(&self) -> usize {
        self.poly_length().get() * self.big_uint_value_len()
    }

    /// Returns the coefficient count of one RNS polynomial.
    pub fn rns_poly_len(&self) -> usize {
        self.inner.size.rns_poly_len()
    }

    /// Returns the coefficient count of one RNS GLWE ciphertext.
    pub fn rns_glwe_len(&self) -> usize {
        self.inner.size.rns_glwe_len()
    }

    /// Returns the coefficient count of the RNS secret-key mask.
    pub fn secret_key_len(&self) -> usize {
        self.inner.size.rns_mask_len()
    }

    /// Returns the underlying single-modulus GLWE layout.
    pub fn glwe_size(&self) -> GlweSize {
        self.inner.size.glwe_size()
    }
}

/// CRT GLev/GGSW parameters for gadget encryption under the product modulus Q.
///
/// These reuse the source GLWE layout and prepared sampling state. The gadget
/// owns its ordered RNS base, decomposition basis and cached level weights;
/// plaintext encoding and BFV scaling are not part of this parameter type.
#[derive(Clone)]
pub struct CrtGlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    inner: Arc<CrtGlweParametersInner<T>>,
    size: RnsGadgetSize,
    base_q: RNSBase<T, M>,
    cipher_moduli_value: Vec<T>,
    basis: BigUintApproxSignedBasis<T>,
    /// Reconstruction weights in level-major order, then ordered RNS modulus.
    scalar_residues: Vec<T>,
}

impl<T, M> CrtGlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a new [`CrtGlevParameters<T, M>`] from matching GLWE parameters.
    ///
    /// # Panics
    ///
    /// Panics if [`Self::try_with_glwe_params`] rejects the decomposition parameters.
    #[must_use]
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &CrtGlweParameters<T, M>,
        log_basis: DecompositionBaseLog,
        reverse_length: Option<DecompositionLevelCount>,
    ) -> Self {
        Self::try_with_glwe_params(glwe_params, log_basis, reverse_length)
            .unwrap_or_else(|error| panic!("failed to construct CRT GLev parameters: {error}"))
    }

    /// Creates a [`CrtGlevParameters<T, M>`] with checked decomposition and layout.
    /// It uses the ordered RNS base owned by `glwe_params`.
    ///
    /// The radix `2^log_basis` must be strictly smaller than every RNS modulus,
    /// as required by the fast centered lift used by CRT/DCRT gadget products.
    ///
    /// # Errors
    ///
    /// Returns [`CrtGlevParametersError`] if decomposition construction fails,
    /// a modulus does not satisfy the centered-lift precondition, or a derived
    /// gadget storage length overflows.
    pub fn try_with_glwe_params(
        glwe_params: &CrtGlweParameters<T, M>,
        log_basis: DecompositionBaseLog,
        reverse_length: Option<DecompositionLevelCount>,
    ) -> Result<Self, CrtGlevParametersError<T>> {
        let basis = BigUintApproxSignedBasis::try_new(
            glwe_params.cipher_modulus(),
            log_basis,
            reverse_length,
        )?;
        for (index, &modulus) in glwe_params.cipher_moduli_value().iter().enumerate() {
            if basis.basis_value() >= modulus {
                return Err(CrtGlevParametersError::BasisNotSmallerThanModulus {
                    basis: basis.basis_value(),
                    modulus,
                    index,
                });
            }
        }
        let size = RnsGadgetSize::try_new(glwe_params.size(), basis.decompose_length())?;
        // L*m weights fit because the checked gadget layout contains
        // L*m*(k+1)*N coefficients. Validate that layout before allocating.
        let mut scalar_residues =
            vec![T::ZERO; basis.decompose_length().get() * glwe_params.cipher_moduli_count()];
        for (scalar, residues) in basis
            .scalar_iter()
            .zip(scalar_residues.chunks_exact_mut(glwe_params.cipher_moduli_count()))
        {
            glwe_params
                .base_q()
                .decompose_to(BigUint(scalar), &mut Residues(residues));
        }
        Ok(Self {
            inner: Arc::clone(&glwe_params.inner),
            base_q: glwe_params.base_q().clone(),
            cipher_moduli_value: glwe_params.cipher_moduli_value().to_vec(),
            basis,
            scalar_residues,
            size,
        })
    }

    /// Returns the dimension of this [`CrtGlevParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> GlweDimension {
        self.size.rns_glwe_size().dimension()
    }

    /// Returns the poly length of this [`CrtGlevParameters<T, M>`].
    #[must_use]
    #[inline]
    pub fn poly_length(&self) -> PolyLength {
        self.size.rns_glwe_size().poly_length()
    }

    /// Returns a reference to the cipher modulus of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> BigUint<&[T]> {
        self.base_q.moduli_product()
    }

    /// Returns a reference to the cipher modulus minus one of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> BigUint<&[T]> {
        self.inner.cipher_modulus_minus_one.view()
    }

    /// Returns the big uint value len of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.base_q.big_uint_value_len()
    }

    /// Returns a reference to the moduli of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn cipher_moduli(&self) -> &[M] {
        self.base_q.moduli()
    }

    /// Returns the moduli count of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn cipher_moduli_count(&self) -> usize {
        self.base_q.moduli_count()
    }

    /// Returns a reference to the cipher moduli value of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_moduli_value(&self) -> &[T] {
        &self.cipher_moduli_value
    }

    /// Returns a reference to the cipher moduli minus one of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_moduli_minus_one(&self) -> &[T] {
        &self.inner.cipher_moduli_minus_one
    }

    /// Returns a reference to the cipher moduli uniform distr of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<T>] {
        &self.inner.cipher_moduli_uniform_distr
    }

    /// Returns the ordered ciphertext RNS basis.
    #[inline]
    pub fn base_q(&self) -> &RNSBase<T, M> {
        &self.base_q
    }

    /// Returns the secret key type of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.inner.secret_key_sampler.distr()
    }

    /// Returns a reference to the noise distribution of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(&self) -> &SignedDiscreteGaussian<T::SignedInteger> {
        &self.inner.noise_distribution
    }

    /// Returns the noise standard deviation of this  [`CrtGlevParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.inner.noise_distribution.standard_deviation()
    }

    /// Returns a reference to the basis of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns cached reconstruction weights modulo each ciphertext modulus.
    ///
    /// Levels follow [`BigUintApproxSignedBasis::decomposer_iter`] from low
    /// to high. Each chunk contains one residue per modulus, in the order of
    /// [`Self::cipher_moduli`]. The weights are computed once at construction.
    #[inline]
    pub fn scalar_residue_iter(
        &self,
    ) -> impl ExactSizeIterator<Item = Residues<&[T]>> + DoubleEndedIterator {
        self.scalar_residues
            .chunks_exact(self.cipher_moduli_count())
            .map(Residues)
    }

    /// Returns the cached RNS gadget layout.
    pub fn size(&self) -> RnsGadgetSize {
        self.size
    }

    /// Returns the coefficient count of one RNS GLev ciphertext.
    pub fn rns_glev_len(&self) -> usize {
        self.size.rns_glev_len()
    }

    /// Returns the coefficient count of one RNS GGSW ciphertext.
    pub fn rns_ggsw_len(&self) -> usize {
        self.size.rns_ggsw_len()
    }

    /// Returns the coefficient count of one RNS polynomial.
    pub fn rns_poly_len(&self) -> usize {
        self.size.rns_glwe_size().rns_poly_len()
    }

    /// Returns the coefficient count of one RNS GLWE ciphertext.
    pub fn rns_glwe_len(&self) -> usize {
        self.size.rns_glwe_size().rns_glwe_len()
    }

    /// Returns the number of decomposition levels.
    #[must_use]
    pub fn decompose_length(&self) -> DecompositionLevelCount {
        self.basis.decompose_length()
    }

    /// Returns the limb length of one polynomial in big-integer representation.
    pub fn big_uint_poly_len(&self) -> usize {
        self.poly_length().get() * self.big_uint_value_len()
    }
}

/// CRT GGSW parameters, sharing the GLev decomposition and sampling configuration.
pub type CrtGgswParameters<T, M> = CrtGlevParameters<T, M>;
