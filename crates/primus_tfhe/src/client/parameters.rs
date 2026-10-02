use primus_distr::DiscreteGaussian;
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::LweParameters;
use primus_reduce::RingContext;
use rand::distr::Uniform;

use super::ClientError;

/// Borrowed parameters for rounded messages in one external LWE domain.
///
/// Construction reuses the mask sampler derived from the codec's ciphertext modulus.
/// Families select the active secret dimension and fresh-encryption noise once;
/// this view contains no family key, PBS order or transform-specific state.
///
/// # Correctness
///
/// Secret coefficients inherit [`primus_lwe::LweSecretKeyRef`]'s range contracts.
/// Noise must fit the message and programmable-bootstrap input budgets;
/// constructor checks establish sampler compatibility, not a noise budget.
#[derive(Clone, Copy)]
pub struct LweClientParameters<'a, T: FheUint, M: RingContext<T>> {
    dimension: LweDimension,
    codec: &'a RoundedCodec<T, M>,
    uniform: Uniform<T>,
    noise: &'a DiscreteGaussian<T>,
}

impl<'a, T: FheUint, M: RingContext<T>> LweClientParameters<'a, T, M> {
    /// Creates [`LweClientParameters`] from one validated LWE parameter set.
    #[must_use]
    pub fn new(parameters: &'a LweParameters<T, M>) -> Self {
        let codec = parameters.plaintext_codec();
        Self {
            dimension: parameters.dimension(),
            codec,
            uniform: parameters.cipher_modulus_uniform_distr(),
            noise: parameters.noise_distribution(),
        }
    }

    /// Creates [`LweClientParameters`] with an alternate secret dimension and noise.
    ///
    /// Keeps the validated LWE codec and its derived mask sampler, and rejects a
    /// noise sampler using another ciphertext modulus. GLWE KS→BR uses this
    /// constructor for the extracted `kN` secret and accumulator noise instead
    /// of the small-LWE dimension and noise. The caller selects the matching key
    /// and remains responsible for the noise budget.
    pub fn try_with_dimension_and_noise(
        parameters: &'a LweParameters<T, M>,
        dimension: LweDimension,
        noise: &'a DiscreteGaussian<T>,
    ) -> Result<Self, ClientError> {
        if noise.modulus_minus_one() != parameters.cipher_modulus_minus_one() {
            return Err(ClientError::NoiseModulusMismatch);
        }
        Ok(Self {
            dimension,
            noise,
            ..Self::new(parameters)
        })
    }

    /// Returns the external LWE dimension.
    #[must_use]
    #[inline]
    pub fn dimension(&self) -> LweDimension {
        self.dimension
    }

    /// Returns the rounded message codec and ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn codec(&self) -> &'a RoundedCodec<T, M> {
        self.codec
    }

    /// Returns the prepared mask sampler derived from the ciphertext modulus.
    #[must_use]
    #[inline]
    pub fn uniform(&self) -> Uniform<T> {
        self.uniform
    }

    /// Returns the selected fresh-encryption noise sampler.
    #[must_use]
    #[inline]
    pub fn noise(&self) -> &'a DiscreteGaussian<T> {
        self.noise
    }
}
