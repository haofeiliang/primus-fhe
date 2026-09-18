//! Parameters for GLWE-based TFHE.

use crate::TfheParameterError;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::DecompositionConfig;

use crate::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, LweParameters,
    SecretKeyDistr,
};

/// Execution order of programmable bootstrapping and key switching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbsOrder {
    /// Blind rotation is followed by a GLWE key switch and compact sample
    /// extraction back to the small LWE key.
    BootstrapKeyswitch,
    /// A GLWE key switch and compact sample extraction first produce a small
    /// LWE ciphertext, which is then bootstrapped.
    KeyswitchBootstrap,
}

/// GLWE-TFHE choices with one shared plaintext/ciphertext modulus domain.
///
/// The accumulator and padded key-switch target inherit `t` and `q` from
/// `small_lwe`. Blind rotation and key switching use the accumulator noise,
/// as in [`TfheParameters::try_new`].
#[derive(Clone)]
pub struct TfheConfig<T: FheUint, M: RingContext<T>> {
    /// Input secret, dimension, moduli and fresh LWE encryption noise.
    pub small_lwe: LweParameters<T, M>,
    /// Number of secret polynomials in the accumulator.
    pub accumulator_dimension: usize,
    /// Accumulator polynomial length `N`.
    pub poly_length: usize,
    /// Coefficient distribution of the accumulator secret.
    pub accumulator_secret_key_distr: SecretKeyDistr,
    /// Standard deviation for accumulator and evaluation-key encryption.
    pub accumulator_noise_standard_deviation: f64,
    /// GGSW decomposition for blind rotation.
    pub blind_rotation: DecompositionConfig,
    /// Decomposition for the GLWE key switch.
    pub key_switching: DecompositionConfig,
    /// Order determining the external LWE secret domain.
    pub pbs_order: PbsOrder,
}

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M, M> {
    /// Derives accumulator and gadget parameters from named independent choices.
    ///
    /// Returns the compatibility and basis errors of [`Self::try_new`].
    ///
    /// # Panics
    ///
    /// Inherits [`GlweParameters::new`]'s layout, sampler and codec requirements.
    pub fn try_from_config(config: TfheConfig<T, M>) -> Result<Self, TfheParameterError> {
        let modulus = config.small_lwe.cipher_modulus();
        let accumulator = GlweParameters::new(
            config.accumulator_dimension,
            config.poly_length,
            config.small_lwe.plain_modulus_value(),
            modulus,
            config.accumulator_secret_key_distr,
            config.accumulator_noise_standard_deviation,
        );
        let blind_rotation = config
            .blind_rotation
            .try_build(modulus)
            .map_err(|error| TfheParameterError::BootstrappingParameters(error.into()))?;
        let key_switching = config
            .key_switching
            .try_build(modulus)
            .map_err(|error| TfheParameterError::KeySwitchingParameters(error.into()))?;
        Self::try_new(
            config.small_lwe,
            accumulator,
            blind_rotation,
            key_switching,
            config.pbs_order,
        )
    }
}

/// Mathematical parameters for GLWE-based TFHE.
///
/// This type is independent of the Fourier or NTT execution backend. A
/// backend-specific context binds it to an FFT/NTT table and validates the
/// table separately.
#[derive(Clone)]
pub struct TfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    small_lwe: LweParameters<T, LM>,
    accumulator_glwe: GlweParameters<T, GM>,
    blind_rotation_ggsw: GgswParameters<T, GM>,
    glwe_key_switching: GlweKeySwitchingParameters<T, GM>,
    pbs_order: PbsOrder,
}

impl<T, LM, GM> TfheParameters<T, LM, GM>
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
        blind_rotation_basis: ApproxSignedBasis<T>,
        key_switching_basis: ApproxSignedBasis<T>,
        pbs_order: PbsOrder,
    ) -> Result<Self, TfheParameterError> {
        let distribution = small_lwe.secret_key_distr();
        if !distribution.is_binary() && !distribution.is_ternary() {
            return Err(TfheParameterError::UnsupportedInputLweSecretKey);
        }
        if small_lwe.plain_modulus_value() != accumulator_glwe.plain_modulus_value() {
            return Err(TfheParameterError::PlainModulusMismatch);
        }

        let capacity = accumulator_glwe.secret_key_len();
        if small_lwe.dimension() > capacity {
            return Err(TfheParameterError::SmallLweDimensionExceedsGlweCapacity {
                small_lwe_dimension: small_lwe.dimension(),
                capacity,
            });
        }
        if small_lwe.cipher_modulus_value() != accumulator_glwe.cipher_modulus_value() {
            return Err(TfheParameterError::CipherModulusMismatch);
        }
        if T::try_from(accumulator_glwe.poly_length() * 2).is_err() {
            return Err(TfheParameterError::RotationDomainTooLarge);
        }
        let blind_rotation_ggsw =
            GgswParameters::try_with_basis(&accumulator_glwe, blind_rotation_basis)
                .map_err(TfheParameterError::BootstrappingParameters)?;
        let glwe_key_switching = Self::derive_glwe_key_switching(
            small_lwe.dimension(),
            small_lwe.secret_key_distr(),
            &accumulator_glwe,
            key_switching_basis,
        )?;
        Ok(Self {
            small_lwe,
            accumulator_glwe,
            blind_rotation_ggsw,
            glwe_key_switching,
            pbs_order,
        })
    }

    fn derive_glwe_key_switching(
        small_lwe_dimension: usize,
        small_lwe_distr: SecretKeyDistr,
        accumulator_glwe: &GlweParameters<T, GM>,
        basis: ApproxSignedBasis<T>,
    ) -> Result<GlweKeySwitchingParameters<T, GM>, TfheParameterError> {
        let output_dimension = small_lwe_dimension.div_ceil(accumulator_glwe.poly_length());
        let output_glwe = GlweParameters::new(
            output_dimension,
            accumulator_glwe.poly_length(),
            accumulator_glwe.plain_modulus_value(),
            accumulator_glwe.cipher_modulus(),
            small_lwe_distr,
            accumulator_glwe.noise_distribution().standard_deviation(),
        );
        let output = GlevParameters::try_with_basis(&output_glwe, basis)
            .map_err(TfheParameterError::KeySwitchingParameters)?;
        Ok(GlweKeySwitchingParameters::new(
            accumulator_glwe.dimension(),
            output,
        ))
    }

    /// Returns the small-LWE parameters used by the bootstrapping key.
    #[must_use]
    #[inline]
    pub fn small_lwe(&self) -> &LweParameters<T, LM> {
        &self.small_lwe
    }

    /// Returns the GGSW encryption and decomposition parameters for blind-rotation controls.
    #[must_use]
    #[inline]
    pub fn blind_rotation_ggsw(&self) -> &GgswParameters<T, GM> {
        &self.blind_rotation_ggsw
    }

    /// Returns the GLWE accumulator parameters.
    #[must_use]
    #[inline]
    pub fn accumulator_glwe(&self) -> &GlweParameters<T, GM> {
        &self.accumulator_glwe
    }

    /// Returns the GLWE key-switching parameters shared by both PBS orders.
    #[must_use]
    #[inline]
    pub fn glwe_key_switching(&self) -> &GlweKeySwitchingParameters<T, GM> {
        &self.glwe_key_switching
    }

    /// Returns the selected PBS execution order.
    #[must_use]
    #[inline]
    pub fn pbs_order(&self) -> PbsOrder {
        self.pbs_order
    }

    /// Returns the dimension of ciphertexts exposed by the client API.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> usize {
        match self.pbs_order() {
            PbsOrder::BootstrapKeyswitch => self.small_lwe.dimension(),
            PbsOrder::KeyswitchBootstrap => self.accumulator_glwe.secret_key_len(),
        }
    }

    /// Returns the plaintext modulus shared by LWE ciphertexts and the GLWE
    /// accumulator.
    #[must_use]
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.small_lwe.plain_modulus_value()
    }

    /// Returns the rounded encoding shared by client inputs and LUT input domains.
    /// LUT outputs may use a different codec; the accumulator's fixed-scale
    /// GLWE codec does not determine the PBS input encoding.
    #[must_use]
    #[inline]
    pub fn input_plaintext_codec(&self) -> &RoundedCodec<T, LM> {
        self.small_lwe.plaintext_codec()
    }
}
