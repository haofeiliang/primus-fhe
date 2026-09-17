//! Parameters for GLWE-based TFHE.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::GlevParameterError;
use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, LweParameters,
    SecretKeyDistr,
};

/// Execution order of programmable bootstrapping and key switching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlwePbsOrder {
    /// Blind rotation is followed by a GLWE key switch and compact sample
    /// extraction back to the small LWE key.
    BootstrapKeyswitch,
    /// A GLWE key switch and compact sample extraction first produce a small
    /// LWE ciphertext, which is then bootstrapped.
    KeyswitchBootstrap,
}

/// An invalid combination of GLWE-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GlweParameterError {
    /// Classic blind rotation supports binary and ternary input LWE secrets.
    #[error("TFHE bootstrapping requires a binary or ternary input LWE secret key")]
    UnsupportedInputLweSecretKey,

    /// The rotation domain `2N` cannot be represented by the input coefficient type.
    #[error("rotation domain must fit the input coefficient type")]
    RotationDomainTooLarge,

    /// The LWE ciphertext and GLWE accumulator use different plaintext spaces.
    #[error("LWE and GLWE plaintext moduli must match")]
    PlainModulusMismatch,

    /// The bootstrapping basis or gadget layout is incompatible with the accumulator.
    #[error("invalid GLWE bootstrapping parameters: {0}")]
    BootstrappingParameters(GlevParameterError),

    /// The small LWE key does not fit in the main GLWE key capacity and
    /// therefore cannot be represented as a padded GLWE key with `k' <= k`.
    #[error(
        "small LWE dimension {small_lwe_dimension} exceeds GLWE secret-key capacity {capacity}"
    )]
    SmallLweDimensionExceedsGlweCapacity {
        /// Configured small LWE dimension.
        small_lwe_dimension: usize,
        /// Main GLWE secret-key capacity `kN`.
        capacity: usize,
    },

    /// GLWE key switching and compact extraction require matching small-LWE
    /// and GLWE ciphertext moduli.
    #[error("TFHE GLWE key switching requires matching LWE and GLWE ciphertext moduli")]
    CipherModulusMismatch,

    /// The GLWE key-switching basis or output gadget layout is incompatible.
    #[error("invalid GLWE key-switching parameters: {0}")]
    KeySwitchingParameters(#[from] GlevParameterError),
}

/// Mathematical parameters for GLWE-based TFHE.
///
/// This type is independent of the Fourier or NTT execution backend. A
/// backend-specific context binds it to an FFT/NTT table and validates the
/// table separately.
#[derive(Clone)]
pub struct GlweTfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    small_lwe: LweParameters<T, LM>,
    glwe: GlweParameters<T, GM>,
    bootstrapping: GgswParameters<T, GM>,
    glwe_key_switching: GlweKeySwitchingParameters<T, GM>,
    pbs_order: GlwePbsOrder,
}

impl<T, LM, GM> GlweTfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Derives bootstrapping parameters and the padded GLWE key-switching layout
    /// from one accumulator description.
    ///
    /// Both gadget bases must belong to the accumulator modulus. Bootstrapping
    /// uses its layout, secret distribution and noise; key switching inherits
    /// its noise while targeting the padded binary or ternary `small_lwe` secret.
    ///
    /// # Errors
    ///
    /// Returns an error for incompatible secrets, plaintext/ciphertext moduli,
    /// dimensions or decomposition bases, a rotation domain `2N` not representable
    /// by `T`, or a derived gadget layout overflow.
    pub fn try_new(
        small_lwe: LweParameters<T, LM>,
        accumulator_glwe: GlweParameters<T, GM>,
        bootstrapping_basis: ApproxSignedBasis<T>,
        key_switching_basis: ApproxSignedBasis<T>,
        pbs_order: GlwePbsOrder,
    ) -> Result<Self, GlweParameterError> {
        let distribution = small_lwe.secret_key_distr();
        if !distribution.is_binary() && !distribution.is_ternary() {
            return Err(GlweParameterError::UnsupportedInputLweSecretKey);
        }
        if small_lwe.plain_modulus_value() != accumulator_glwe.plain_modulus_value() {
            return Err(GlweParameterError::PlainModulusMismatch);
        }

        let capacity = accumulator_glwe.secret_key_len();
        if small_lwe.dimension() > capacity {
            return Err(GlweParameterError::SmallLweDimensionExceedsGlweCapacity {
                small_lwe_dimension: small_lwe.dimension(),
                capacity,
            });
        }
        if small_lwe.cipher_modulus_value() != accumulator_glwe.cipher_modulus_value() {
            return Err(GlweParameterError::CipherModulusMismatch);
        }
        if T::try_from(accumulator_glwe.poly_length() * 2).is_err() {
            return Err(GlweParameterError::RotationDomainTooLarge);
        }
        let bootstrapping = GgswParameters::try_with_basis(&accumulator_glwe, bootstrapping_basis)
            .map_err(GlweParameterError::BootstrappingParameters)?;
        let glwe_key_switching = Self::derive_glwe_key_switching(
            small_lwe.dimension(),
            small_lwe.secret_key_distr(),
            &accumulator_glwe,
            key_switching_basis,
        )?;
        Ok(Self {
            small_lwe,
            glwe: accumulator_glwe,
            bootstrapping,
            glwe_key_switching,
            pbs_order,
        })
    }

    fn derive_glwe_key_switching(
        small_lwe_dimension: usize,
        small_lwe_distr: SecretKeyDistr,
        glwe: &GlweParameters<T, GM>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<GlweKeySwitchingParameters<T, GM>, GlweParameterError> {
        let output_dimension = small_lwe_dimension.div_ceil(glwe.poly_length());
        let output_glwe = GlweParameters::new(
            output_dimension,
            glwe.poly_length(),
            glwe.plain_modulus_value(),
            glwe.cipher_modulus(),
            small_lwe_distr,
            glwe.noise_distribution().standard_deviation(),
        );
        let output = GlevParameters::try_with_basis(&output_glwe, basis)?;
        Ok(GlweKeySwitchingParameters::new(glwe.dimension(), output))
    }

    /// Returns the small-LWE parameters used by the bootstrapping key.
    #[inline]
    pub fn small_lwe(&self) -> &LweParameters<T, LM> {
        &self.small_lwe
    }

    /// Returns the GGSW parameters used by programmable bootstrapping.
    #[inline]
    pub fn bootstrapping(&self) -> &GgswParameters<T, GM> {
        &self.bootstrapping
    }

    /// Returns the GLWE accumulator parameters.
    #[inline]
    pub fn glwe(&self) -> &crate::GlweParameters<T, GM> {
        &self.glwe
    }

    /// Returns the GLWE key-switching parameters shared by both PBS orders.
    #[inline]
    pub fn glwe_key_switching(&self) -> &GlweKeySwitchingParameters<T, GM> {
        &self.glwe_key_switching
    }

    /// Returns the selected PBS execution order.
    #[inline]
    pub fn pbs_order(&self) -> GlwePbsOrder {
        self.pbs_order
    }

    /// Returns the dimension of ciphertexts exposed by the client API.
    #[inline]
    pub fn ciphertext_lwe_dimension(&self) -> usize {
        match self.pbs_order() {
            GlwePbsOrder::BootstrapKeyswitch => self.small_lwe.dimension(),
            GlwePbsOrder::KeyswitchBootstrap => self.glwe.secret_key_len(),
        }
    }

    /// Returns the plaintext modulus shared by LWE ciphertexts and the GLWE
    /// accumulator.
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.small_lwe.plain_modulus_value()
    }
}
