//! Immutable layout and sampling precomputation shared by RNS parameter roles.

use primus_distr::{SecretKeySampler, SignedDiscreteGaussian};
use primus_integer::{BigUint, FheUint};
use primus_lattice::RnsGlweSize;
use primus_reduce::FieldContext;
use primus_rns::RNSBase;
use rand::distr::Uniform;

use super::CrtGlweParametersError;
use crate::SecretKeyDistr;

/// Layout and sampling state shared by ordinary and gadget parameters.
///
/// Base-dependent caches follow the immutable ordered base owned by each outer
/// type: the ordinary codec or the gadget base. No second RNSBase is stored here.
/// Arc sharing retains the same prepared Gaussian tables and secret sampler when
/// gadget parameters are derived, instead of cloning those precomputations.
pub(super) struct CrtGlweParametersInner<T: FheUint> {
    pub(super) size: RnsGlweSize,
    pub(super) cipher_modulus_minus_one: BigUint<Vec<T>>,
    pub(super) cipher_moduli_minus_one: Vec<T>,
    pub(super) cipher_moduli_uniform_distr: Vec<Uniform<T>>,
    pub(super) secret_key_sampler: SecretKeySampler<T>,
    pub(super) noise_distribution: SignedDiscreteGaussian<T::SignedInteger>,
}

impl<T: FheUint> CrtGlweParametersInner<T> {
    /// Prepares the complete kN secret and noise domains once at construction.
    /// The base is already valid and size has the same ordered modulus count.
    pub(super) fn try_new<M: FieldContext<T>>(
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
