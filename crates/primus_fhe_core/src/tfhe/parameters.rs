//! Parameters for GLWE-based TFHE.

use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, LweParameters,
    LweSecretKeyType, RingSecretKeyType,
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

/// An invalid combination of GLWE-based TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheParameterError {
    /// The current functional bootstrapping-key implementation requires a
    /// binary input LWE secret key.
    #[error("TFHE bootstrapping requires a binary input LWE secret key")]
    InputLweSecretKeyMustBeBinary,

    /// The LWE ciphertext and GLWE accumulator use different plaintext spaces.
    #[error("LWE and GLWE plaintext moduli must match")]
    PlainModulusMismatch,

    /// The GGSW parameters were not derived from the configured accumulator
    /// GLWE parameters.
    #[error("bootstrapping GLWE parameters do not match the accumulator GLWE parameters")]
    BootstrappingGlweParametersMismatch,

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

    /// The requested GLWE key-switch decomposition cannot be constructed.
    #[error("invalid GLWE key-switching decomposition: {0}")]
    InvalidGlweKeySwitchingDecomposition(#[source] primus_decompose::ApproxSignedBasisError),
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
    glwe: GlweParameters<T, GM>,
    bootstrapping: GgswParameters<T, GM>,
    glwe_key_switching: GlweKeySwitchingParameters<T, GM>,
    pbs_order: PbsOrder,
}

impl<T, LM, GM> TfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates parameters while deriving the padded GLWE key-switching layout.
    ///
    /// `key_switching_log_basis` and `key_switching_level_count` configure the
    /// GLWE key switch used by the selected `pbs_order`; the bootstrapping
    /// decomposition remains part of `bootstrapping`.
    ///
    /// `key_switching_level_count`, when provided, limits the number of GLWE
    /// key-switching decomposition levels. `None` uses the full decomposition.
    ///
    /// # Errors
    ///
    /// Returns an error when the LWE, GLWE, and bootstrapping parameters do not
    /// form one TFHE parameter set, or when the requested key-switching
    /// decomposition cannot be constructed.
    pub fn try_new(
        small_lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        key_switching_log_basis: u32,
        key_switching_level_count: Option<usize>,
        pbs_order: PbsOrder,
    ) -> Result<Self, TfheParameterError> {
        Self::validate_common(&small_lwe, &glwe, &bootstrapping)?;

        let capacity = glwe.secret_key_len();
        if small_lwe.dimension() > capacity {
            return Err(TfheParameterError::SmallLweDimensionExceedsGlweCapacity {
                small_lwe_dimension: small_lwe.dimension(),
                capacity,
            });
        }
        if small_lwe.cipher_modulus().explicit_value() != glwe.cipher_modulus().explicit_value() {
            return Err(TfheParameterError::CipherModulusMismatch);
        }

        let glwe_key_switching = Self::derive_glwe_key_switching(
            small_lwe.dimension(),
            &glwe,
            key_switching_log_basis,
            key_switching_level_count,
        )?;
        Ok(Self {
            small_lwe,
            glwe,
            bootstrapping,
            glwe_key_switching,
            pbs_order,
        })
    }

    fn derive_glwe_key_switching(
        small_lwe_dimension: usize,
        glwe: &GlweParameters<T, GM>,
        key_switching_log_basis: u32,
        key_switching_level_count: Option<usize>,
    ) -> Result<GlweKeySwitchingParameters<T, GM>, TfheParameterError> {
        let output_dimension = small_lwe_dimension.div_ceil(glwe.poly_length());
        let output_glwe = GlweParameters::new(
            output_dimension,
            glwe.poly_length(),
            glwe.plain_modulus_value(),
            glwe.cipher_modulus(),
            RingSecretKeyType::Binary,
            glwe.noise_distribution().standard_deviation(),
        );
        let output = GlevParameters::try_with_glwe_params(
            &output_glwe,
            key_switching_log_basis,
            key_switching_level_count,
        )
        .map_err(TfheParameterError::InvalidGlweKeySwitchingDecomposition)?;
        Ok(GlweKeySwitchingParameters::new(glwe.dimension(), output))
    }

    fn validate_common(
        small_lwe: &LweParameters<T, LM>,
        glwe: &GlweParameters<T, GM>,
        bootstrapping: &GgswParameters<T, GM>,
    ) -> Result<(), TfheParameterError> {
        if small_lwe.secret_key_type() != LweSecretKeyType::Binary {
            return Err(TfheParameterError::InputLweSecretKeyMustBeBinary);
        }

        if small_lwe.plain_modulus_value() != glwe.plain_modulus_value() {
            return Err(TfheParameterError::PlainModulusMismatch);
        }

        if glwe.size() != bootstrapping.glwe_size() || glwe.inner() != bootstrapping.inner() {
            return Err(TfheParameterError::BootstrappingGlweParametersMismatch);
        }

        Ok(())
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
    pub fn pbs_order(&self) -> PbsOrder {
        self.pbs_order
    }

    /// Returns the dimension of ciphertexts exposed by the client API.
    #[inline]
    pub fn ciphertext_lwe_dimension(&self) -> usize {
        match self.pbs_order() {
            PbsOrder::BootstrapKeyswitch => self.small_lwe.dimension(),
            PbsOrder::KeyswitchBootstrap => self.glwe.secret_key_len(),
        }
    }

    /// Returns the plaintext modulus shared by LWE ciphertexts and the GLWE
    /// accumulator.
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.small_lwe.plain_modulus_value()
    }
}
