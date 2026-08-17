//! Parameters for GLWE-based TFHE.

use primus_decompose::primitive::ApproxSignedBasis;
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

    /// The GLWE key-switching basis belongs to a different ciphertext modulus.
    #[error("GLWE key-switching basis modulus must match the GLWE ciphertext modulus")]
    KeySwitchingBasisModulusMismatch,
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
    /// Creates parameters while deriving the padded GLWE key-switching layout.
    ///
    /// `key_switching_basis` configures the GLWE key switch used by the selected
    /// `pbs_order`; the bootstrapping basis remains part of `bootstrapping`.
    ///
    /// # Errors
    ///
    /// Returns an error when the LWE, GLWE, and bootstrapping parameters do not
    /// form one TFHE parameter set.
    pub fn try_new(
        small_lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        key_switching_basis: ApproxSignedBasis<T>,
        pbs_order: GlwePbsOrder,
    ) -> Result<Self, GlweParameterError> {
        Self::validate_common(&small_lwe, &glwe, &bootstrapping)?;

        let capacity = glwe.secret_key_len();
        if small_lwe.dimension() > capacity {
            return Err(GlweParameterError::SmallLweDimensionExceedsGlweCapacity {
                small_lwe_dimension: small_lwe.dimension(),
                capacity,
            });
        }
        if small_lwe.cipher_modulus().explicit_value() != glwe.cipher_modulus().explicit_value() {
            return Err(GlweParameterError::CipherModulusMismatch);
        }
        if key_switching_basis.modulus() != glwe.inner().cipher_modulus_value() {
            return Err(GlweParameterError::KeySwitchingBasisModulusMismatch);
        }

        let glwe_key_switching = Self::derive_glwe_key_switching(
            small_lwe.dimension(),
            small_lwe.secret_key_distr(),
            &glwe,
            key_switching_basis,
        );
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
        small_lwe_distr: SecretKeyDistr,
        glwe: &GlweParameters<T, GM>,
        basis: ApproxSignedBasis<T>,
    ) -> GlweKeySwitchingParameters<T, GM> {
        let output_dimension = small_lwe_dimension.div_ceil(glwe.poly_length());
        let output_glwe = GlweParameters::new(
            output_dimension,
            glwe.poly_length(),
            glwe.plain_modulus_value(),
            glwe.cipher_modulus(),
            small_lwe_distr,
            glwe.noise_distribution().standard_deviation(),
        );
        let full_decompose_length = (basis.value_bits() / basis.log_basis()) as usize;
        let reverse_length =
            (basis.decompose_length() != full_decompose_length).then_some(basis.decompose_length());
        let output =
            GlevParameters::with_glwe_params(&output_glwe, basis.log_basis(), reverse_length);
        GlweKeySwitchingParameters::new(glwe.dimension(), output)
    }

    fn validate_common(
        small_lwe: &LweParameters<T, LM>,
        glwe: &GlweParameters<T, GM>,
        bootstrapping: &GgswParameters<T, GM>,
    ) -> Result<(), GlweParameterError> {
        if !small_lwe.secret_key_distr().is_binary() {
            return Err(GlweParameterError::InputLweSecretKeyMustBeBinary);
        }

        if small_lwe.plain_modulus_value() != glwe.plain_modulus_value() {
            return Err(GlweParameterError::PlainModulusMismatch);
        }

        if glwe.size() != bootstrapping.glwe_size() || glwe.inner() != bootstrapping.inner() {
            return Err(GlweParameterError::BootstrappingGlweParametersMismatch);
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
