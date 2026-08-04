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

    /// The GGSW decomposition basis was created for a different GLWE modulus.
    #[error("bootstrapping decomposition basis does not match the GLWE ciphertext modulus")]
    BootstrappingBasisModulusMismatch,

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

    /// The GLWE key-switching key must start from the main GLWE key.
    #[error("GLWE key-switching input dimension mismatch: expected {expected}, got {actual}")]
    GlweKeySwitchingInputDimensionMismatch {
        /// Main GLWE dimension.
        expected: usize,
        /// Configured key-switch input dimension.
        actual: usize,
    },

    /// The GLWE key-switching output dimension must be the smallest dimension
    /// capable of containing the padded small LWE key.
    #[error("GLWE key-switching output dimension mismatch: expected {expected}, got {actual}")]
    GlweKeySwitchingOutputDimensionMismatch {
        /// Derived padded GLWE dimension.
        expected: usize,
        /// Configured output GLWE dimension.
        actual: usize,
    },

    /// The input and output GLWE keys must use the same polynomial length.
    #[error("GLWE key-switching polynomial length mismatch: expected {expected}, got {actual}")]
    GlweKeySwitchingPolynomialLengthMismatch {
        /// Main GLWE polynomial length.
        expected: usize,
        /// Configured output polynomial length.
        actual: usize,
    },

    /// GLWE key switching must use the main GLWE ciphertext modulus.
    #[error("GLWE key-switching ciphertext modulus does not match the main GLWE modulus")]
    GlweKeySwitchingCipherModulusMismatch,

    /// The output GLWE key is derived from the binary small LWE key.
    #[error("GLWE key-switching output secret-key type must be binary")]
    GlweKeySwitchingOutputSecretKeyMustBeBinary,

    /// The GLWE key-switch decomposition basis uses a different modulus.
    #[error("GLWE key-switching decomposition basis does not match the GLWE ciphertext modulus")]
    GlweKeySwitchingBasisModulusMismatch,

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

/// Component parameter objects owned by a [`TfheParameters`] value.
pub type TfheParameterParts<T, LM, GM> = (
    LweParameters<T, LM>,
    GlweParameters<T, GM>,
    GgswParameters<T, GM>,
    GlweKeySwitchingParameters<T, GM>,
    PbsOrder,
);

impl<T, LM, GM> TfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates parameters while deriving the padded GLWE key-switching layout.
    ///
    /// `key_switching_level_count`, when provided, limits the number of GLWE
    /// key-switching decomposition levels. `None` uses the full decomposition.
    pub fn try_with_derived_glwe_key_switching(
        small_lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        key_switching_log_basis: u32,
        key_switching_level_count: Option<usize>,
        pbs_order: PbsOrder,
    ) -> Result<Self, TfheParameterError> {
        let glwe_key_switching = Self::derive_glwe_key_switching(
            small_lwe.dimension(),
            &glwe,
            key_switching_log_basis,
            key_switching_level_count,
        )?;
        Self::try_new(
            small_lwe,
            glwe,
            bootstrapping,
            glwe_key_switching,
            pbs_order,
        )
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

    /// Creates and validates a GLWE-based TFHE parameter set.
    pub fn try_new(
        small_lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        glwe_key_switching: GlweKeySwitchingParameters<T, GM>,
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
        if glwe_key_switching.input_dimension() != glwe.dimension() {
            return Err(TfheParameterError::GlweKeySwitchingInputDimensionMismatch {
                expected: glwe.dimension(),
                actual: glwe_key_switching.input_dimension(),
            });
        }

        let expected_output_dimension = small_lwe.dimension().div_ceil(glwe.poly_length());
        if glwe_key_switching.output_dimension() != expected_output_dimension {
            return Err(
                TfheParameterError::GlweKeySwitchingOutputDimensionMismatch {
                    expected: expected_output_dimension,
                    actual: glwe_key_switching.output_dimension(),
                },
            );
        }
        if glwe_key_switching.poly_length() != glwe.poly_length() {
            return Err(
                TfheParameterError::GlweKeySwitchingPolynomialLengthMismatch {
                    expected: glwe.poly_length(),
                    actual: glwe_key_switching.poly_length(),
                },
            );
        }
        if glwe_key_switching
            .output()
            .cipher_modulus()
            .explicit_value()
            != glwe.cipher_modulus().explicit_value()
        {
            return Err(TfheParameterError::GlweKeySwitchingCipherModulusMismatch);
        }
        if glwe_key_switching.output().secret_key_type() != RingSecretKeyType::Binary {
            return Err(TfheParameterError::GlweKeySwitchingOutputSecretKeyMustBeBinary);
        }
        if glwe_key_switching.output().basis().modulus() != glwe.cipher_modulus().explicit_value() {
            return Err(TfheParameterError::GlweKeySwitchingBasisModulusMismatch);
        }

        Ok(Self {
            small_lwe,
            glwe,
            bootstrapping,
            glwe_key_switching,
            pbs_order,
        })
    }

    /// Creates bootstrap-then-key-switch parameters from an explicit GLWE
    /// key-switching parameter set.
    #[inline]
    pub fn new_bootstrap_keyswitch(
        small_lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        glwe_key_switching: GlweKeySwitchingParameters<T, GM>,
    ) -> Result<Self, TfheParameterError> {
        Self::try_new(
            small_lwe,
            glwe,
            bootstrapping,
            glwe_key_switching,
            PbsOrder::BootstrapKeyswitch,
        )
    }

    /// Creates key-switch-then-bootstrap parameters from an explicit GLWE
    /// key-switching parameter set.
    #[inline]
    pub fn new_keyswitch_bootstrap(
        small_lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        glwe_key_switching: GlweKeySwitchingParameters<T, GM>,
    ) -> Result<Self, TfheParameterError> {
        Self::try_new(
            small_lwe,
            glwe,
            bootstrapping,
            glwe_key_switching,
            PbsOrder::KeyswitchBootstrap,
        )
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

        if bootstrapping.basis().modulus() != bootstrapping.cipher_modulus().explicit_value() {
            return Err(TfheParameterError::BootstrappingBasisModulusMismatch);
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

    /// Returns the LWE dimension consumed by blind rotation.
    ///
    /// In the key-switch-first flow, compact sample extraction removes the
    /// zero-padded suffix before blind rotation.
    #[inline]
    pub fn blind_rotation_input_dimension(&self) -> usize {
        self.small_lwe.dimension()
    }

    /// Returns the plaintext modulus shared by LWE ciphertexts and the GLWE
    /// accumulator.
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.small_lwe.plain_modulus_value()
    }

    /// Decomposes this parameter set into its component parameter objects.
    #[inline]
    pub fn into_parts(self) -> TfheParameterParts<T, LM, GM> {
        (
            self.small_lwe,
            self.glwe,
            self.bootstrapping,
            self.glwe_key_switching,
            self.pbs_order,
        )
    }
}
