//! RNS (Residue Number System) multi-modulus GLWE / GLev / GGSW parameters.

use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_distr::SignedDiscreteGaussian;
use primus_factor::ShoupFactor;
use primus_integer::{BigUint, FheUint, UnsignedInteger};
use primus_lattice::{GlweSize, RnsGadgetSize, RnsGlweSize};
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use rand::distr::Uniform;

use crate::{RnsCoeffCodec, SecretKeyDistr};

/// Big Unsigned Integer Glwe Parameters.
#[derive(Clone)]
pub struct CrtGlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    size: RnsGlweSize,
    /// The cipher modulus minus one, refers to **Q-1**.
    cipher_modulus_minus_one: BigUint<Vec<T>>,
    /// Refers to `Q1-1`, `Q2-1` ...
    cipher_moduli_minus_one: Vec<T>,
    /// The uniform distribution to sample values over `Q1`, `Q2` ...
    cipher_moduli_uniform_distr: Vec<Uniform<T>>,
    /// BFV-style RNS codec for encoding/decoding plaintext.
    codec: RnsCoeffCodec<T, M>,
    delta_mod_q: Vec<T>,
    /// The distribution type of the secret key.
    secret_key_distr: SecretKeyDistr,
    secret_key_distribution: Option<SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>>,
    /// The noise distribution
    noise_distribution: SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
}

impl<T, M> CrtGlweParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates a new [`CrtGlweParameters<T, M>`].
    pub fn new(
        dimension: usize,
        poly_length: usize,
        plain_modulus: M,
        gamma_modulus: M,
        cipher_moduli: &[M],
        secret_key_distr: SecretKeyDistr,
        noise_standard_deviation: f64,
    ) -> Self {
        let cipher_moduli_value: Vec<T> = cipher_moduli.iter().map(|qi| qi.value()).collect();

        let cipher_moduli_minus_one = cipher_moduli_value.iter().map(|&qi| qi - T::ONE).collect();
        let base_q = RNSBase::new(cipher_moduli).unwrap();
        let cipher_modulus = base_q.moduli_product();
        let cipher_modulus_minus_one = {
            let mut temp = BigUint(cipher_modulus.0.to_vec());
            let _ = temp.sub_value_assign(T::ONE);
            temp
        };

        let codec = RnsCoeffCodec::new(plain_modulus, base_q, gamma_modulus);

        let delta_mod_q: Vec<T> = codec
            .delta_factor_mod_q()
            .iter()
            .map(|f| f.value())
            .collect();

        let cipher_moduli_uniform_distr = cipher_moduli
            .iter()
            .map(|qi| qi.uniform_distribution())
            .collect();

        let noise_distribution = SignedDiscreteGaussian::new(noise_standard_deviation).unwrap();

        let size = RnsGlweSize::new(GlweSize::new(dimension, poly_length), cipher_moduli.len());

        let secret_key_distribution =
            if let SecretKeyDistr::Gaussian(standard_deviation) = secret_key_distr {
                SignedDiscreteGaussian::new(standard_deviation).ok()
            } else {
                None
            };

        Self {
            size,
            cipher_modulus_minus_one,
            cipher_moduli_minus_one,
            cipher_moduli_uniform_distr,
            codec,
            delta_mod_q,
            secret_key_distr,
            secret_key_distribution,
            noise_distribution,
        }
    }

    /// Returns the dimension of this [`CrtGlweParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.size.dimension()
    }

    /// Returns the poly length of this [`CrtGlweParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.size.poly_length()
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
        self.cipher_modulus_minus_one.view()
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
        &self.cipher_moduli_minus_one
    }

    /// Returns the moduli count of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_count(&self) -> usize {
        self.codec.moduli_count()
    }

    /// Returns a reference to the cipher moduli uniform distr of this [`CrtGlweParameters<T, M>`].
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<T>] {
        &self.cipher_moduli_uniform_distr
    }

    /// Returns the big uint value len of this [`CrtGlweParameters<T, M>`].
    #[inline]
    pub fn big_uint_value_len(&self) -> usize {
        self.codec.base_q().big_uint_value_len()
    }

    /// Returns the secret key type of this [`CrtGlweParameters<T, M>`].
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_distr
    }

    /// Returns the secret key distribution of this [`CrtGlweParameters<T, M>`].
    pub fn secret_key_distribution(
        &self,
    ) -> Option<&SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>> {
        self.secret_key_distribution.as_ref()
    }

    /// Returns a reference to the noise distribution of this [`CrtGlweParameters<T, M>`].
    pub fn noise_distribution(
        &self,
    ) -> &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger> {
        &self.noise_distribution
    }

    /// Returns the noise standard deviation of this [`CrtGlweParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_distribution.standard_deviation()
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
    pub fn delta_factor_mod_q(&self) -> &[ShoupFactor<T>] {
        self.codec.delta_factor_mod_q()
    }

    /// Returns the ordered ciphertext RNS basis Q.
    pub fn base_q(&self) -> &RNSBase<T, M> {
        self.codec.base_q()
    }

    /// Returns the plaintext coefficient codec bound to this RNS basis.
    pub fn codec(&self) -> &RnsCoeffCodec<T, M> {
        &self.codec
    }

    /// Returns the cached RNS GLWE layout.
    pub fn size(&self) -> RnsGlweSize {
        self.size
    }

    /// Returns the limb length of one polynomial in big-integer representation.
    pub fn big_uint_poly_len(&self) -> usize {
        self.poly_length() * self.big_uint_value_len()
    }

    /// Returns the coefficient count of one RNS polynomial.
    pub fn rns_poly_len(&self) -> usize {
        self.size.rns_poly_len()
    }

    /// Returns the coefficient count of one RNS GLWE ciphertext.
    pub fn rns_glwe_len(&self) -> usize {
        self.size.rns_glwe_len()
    }

    /// Returns the coefficient count of the RNS secret-key mask.
    pub fn secret_key_len(&self) -> usize {
        self.size.rns_mask_len()
    }

    /// Returns the underlying single-modulus GLWE layout.
    pub const fn glwe_size(&self) -> GlweSize {
        self.size.glwe_size()
    }
}

/// Big Unsigned Integer Ggsw Parameters.
#[derive(Clone)]
pub struct CrtGlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    size: RnsGadgetSize,
    /// cipher modulus minus one, refers to **Q-1**.
    cipher_modulus_minus_one: BigUint<Vec<T>>,
    /// The ordered RNS basis and its CRT precomputations.
    base_q: RNSBase<T, M>,
    /// The moduli, refers to **Q=Q1*Q2*...** in the paper.
    cipher_moduli_value: Vec<T>,
    /// Refers to `Q1-1`, `Q2-1` ...
    cipher_moduli_minus_one: Vec<T>,

    cipher_moduli_uniform_distr: Vec<Uniform<T>>,
    /// The distribution type of the secret key.
    secret_key_distr: SecretKeyDistr,
    /// The noise's distribution.
    noise_distribution: SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger>,
    /// Decompose basis for `Q`.
    basis: BigUintApproxSignedBasis<T>,
}

impl<T, M> CrtGlevParameters<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Creates CRT GLev/GGSW parameters from one matching GLWE parameter set.
    #[inline]
    pub fn with_glwe_params(
        glwe_params: &CrtGlweParameters<T, M>,
        log_basis: u32,
        reverse_length: Option<usize>,
    ) -> Self {
        Self::try_with_glwe_params(glwe_params, log_basis, reverse_length)
            .unwrap_or_else(|error| panic!("failed to construct CRT GLev parameters: {error}"))
    }

    /// Tries to create CRT GLev/GGSW parameters and their basis from the
    /// ordered RNS base owned by `glwe_params`.
    pub fn try_with_glwe_params(
        glwe_params: &CrtGlweParameters<T, M>,
        log_basis: u32,
        reverse_length: Option<usize>,
    ) -> Result<Self, primus_decompose::ApproxSignedBasisError> {
        let basis =
            BigUintApproxSignedBasis::try_new(glwe_params.base_q(), log_basis, reverse_length)?;
        let decompose_length = basis.decompose_length();
        Ok(Self {
            cipher_modulus_minus_one: glwe_params.cipher_modulus_minus_one().into(),
            base_q: glwe_params.base_q().clone(),
            cipher_moduli_value: glwe_params.cipher_moduli_value().to_vec(),
            cipher_moduli_minus_one: glwe_params.cipher_moduli_minus_one().to_vec(),
            cipher_moduli_uniform_distr: glwe_params.cipher_moduli_uniform_distr().to_vec(),
            secret_key_distr: glwe_params.secret_key_distr,
            noise_distribution: glwe_params.noise_distribution().clone(),
            basis,
            size: RnsGadgetSize::new(glwe_params.size(), decompose_length),
        })
    }

    /// Returns the dimension of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn dimension(&self) -> usize {
        self.size.rns_glwe_size().dimension()
    }

    /// Returns the poly length of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn poly_length(&self) -> usize {
        self.size.rns_glwe_size().poly_length()
    }

    /// Returns a reference to the cipher modulus of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn cipher_modulus(&self) -> BigUint<&[T]> {
        self.base_q.moduli_product()
    }

    /// Returns a reference to the cipher modulus minus one of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_modulus_minus_one(&self) -> BigUint<&[T]> {
        self.cipher_modulus_minus_one.view()
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
        &self.cipher_moduli_minus_one
    }

    /// Returns a reference to the cipher moduli uniform distr of this [`CrtGlevParameters<T, M>`].
    pub fn cipher_moduli_uniform_distr(&self) -> &[Uniform<T>] {
        &self.cipher_moduli_uniform_distr
    }

    /// Returns the ordered ciphertext RNS basis.
    #[inline]
    pub fn base_q(&self) -> &RNSBase<T, M> {
        &self.base_q
    }

    /// Returns the secret key type of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn secret_key_distr(&self) -> SecretKeyDistr {
        self.secret_key_distr
    }

    /// Returns a reference to the noise distribution of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn noise_distribution(
        &self,
    ) -> &SignedDiscreteGaussian<<T as UnsignedInteger>::SignedInteger> {
        &self.noise_distribution
    }

    /// Returns the noise standard deviation of this  [`CrtGlevParameters<T, M>`].
    pub fn noise_standard_deviation(&self) -> f64 {
        self.noise_distribution.standard_deviation()
    }

    /// Returns a reference to the basis of this [`CrtGlevParameters<T, M>`].
    #[inline]
    pub fn basis(&self) -> &BigUintApproxSignedBasis<T> {
        &self.basis
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
    pub fn decompose_length(&self) -> usize {
        self.basis.decompose_length()
    }

    /// Returns the limb length of one polynomial in big-integer representation.
    pub fn big_uint_poly_len(&self) -> usize {
        self.poly_length() * self.big_uint_value_len()
    }
}

/// Big Unsigned Integer Ggsw Parameters.
pub type CrtGgswParameters<T, M> = CrtGlevParameters<T, M>;
