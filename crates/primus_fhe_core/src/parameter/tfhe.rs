use primus_decompose::primitive::ApproxSignedBasis;
use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{GgswParameters, GlweParameters, LweParameters, LweSecretKeyType};

/// Parameters controlling an LWE key-switching key.
///
/// The input and output ciphertext moduli are supplied by the corresponding
/// [`LweParameters`] at key generation or evaluation time. Keeping them out of
/// this type avoids cloning complete LWE parameter sets when it is embedded in
/// a higher-level scheme parameter set.
#[derive(Debug, Clone)]
pub struct LweKeySwitchingParameters<T: FheUint> {
    input_dimension: usize,
    output_dimension: usize,
    basis: ApproxSignedBasis<T>,
}

impl<T: FheUint> LweKeySwitchingParameters<T> {
    /// Creates LWE key-switching parameters.
    ///
    /// # Panics
    ///
    /// Panics if either LWE dimension is zero.
    pub fn new(
        input_dimension: usize,
        output_dimension: usize,
        basis: ApproxSignedBasis<T>,
    ) -> Self {
        assert!(input_dimension > 0, "input LWE dimension must be non-zero");
        assert!(
            output_dimension > 0,
            "output LWE dimension must be non-zero"
        );
        Self {
            input_dimension,
            output_dimension,
            basis,
        }
    }

    /// Returns the dimension of ciphertexts before key switching.
    #[inline]
    pub fn input_dimension(&self) -> usize {
        self.input_dimension
    }

    /// Returns the dimension of ciphertexts after key switching.
    #[inline]
    pub fn output_dimension(&self) -> usize {
        self.output_dimension
    }

    /// Returns the decomposition basis used by key switching.
    #[inline]
    pub fn basis(&self) -> &ApproxSignedBasis<T> {
        &self.basis
    }

    /// Returns the decomposition length.
    #[inline]
    pub fn decompose_length(&self) -> usize {
        self.basis.decompose_length()
    }
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

    /// Sample extraction produces an LWE of dimension `k * N`, which must be
    /// the input dimension of the key-switching key.
    #[error(
        "key-switching input dimension mismatch: expected {expected} from GLWE sample extraction, got {actual}"
    )]
    KeySwitchingInputDimensionMismatch {
        /// Expected sample-extracted LWE dimension.
        expected: usize,
        /// Configured key-switching input dimension.
        actual: usize,
    },

    /// Key switching must return ciphertexts under the configured small LWE
    /// secret key.
    #[error(
        "key-switching output dimension mismatch: expected {expected} from LWE parameters, got {actual}"
    )]
    KeySwitchingOutputDimensionMismatch {
        /// Expected output LWE dimension.
        expected: usize,
        /// Configured key-switching output dimension.
        actual: usize,
    },

    /// The key-switch decomposition basis was created for a different
    /// sample-extracted LWE ciphertext modulus.
    #[error(
        "key-switching decomposition basis does not match the sample-extracted LWE ciphertext modulus"
    )]
    KeySwitchingBasisModulusMismatch,
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
    lwe: LweParameters<T, LM>,
    glwe: GlweParameters<T, GM>,
    bootstrapping: GgswParameters<T, GM>,
    key_switching: LweKeySwitchingParameters<T>,
}

/// Component parameter objects owned by a [`TfheParameters`] value.
pub type TfheParameterParts<T, LM, GM> = (
    LweParameters<T, LM>,
    GlweParameters<T, GM>,
    GgswParameters<T, GM>,
    LweKeySwitchingParameters<T>,
);

impl<T, LM, GM> TfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Creates TFHE parameters while deriving the key-switching dimensions
    /// from the GLWE and small-LWE parameter sets.
    ///
    /// This is the preferred constructor for the standard PBS-then-key-switch
    /// flow. Use [`Self::try_new`] when importing an independently specified
    /// key-switching parameter set.
    pub fn with_key_switching_basis(
        lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        key_switching_basis: ApproxSignedBasis<T>,
    ) -> Result<Self, TfheParameterError> {
        let key_switching = LweKeySwitchingParameters::new(
            glwe.secret_key_len(),
            lwe.dimension(),
            key_switching_basis,
        );
        Self::try_new(lwe, glwe, bootstrapping, key_switching)
    }

    /// Creates and validates a GLWE-based TFHE parameter set.
    pub fn try_new(
        lwe: LweParameters<T, LM>,
        glwe: GlweParameters<T, GM>,
        bootstrapping: GgswParameters<T, GM>,
        key_switching: LweKeySwitchingParameters<T>,
    ) -> Result<Self, TfheParameterError> {
        if lwe.secret_key_type() != LweSecretKeyType::Binary {
            return Err(TfheParameterError::InputLweSecretKeyMustBeBinary);
        }

        if lwe.plain_modulus_value() != glwe.plain_modulus_value() {
            return Err(TfheParameterError::PlainModulusMismatch);
        }

        if glwe.common_size() != bootstrapping.glwe_common_size()
            || glwe.cipher_modulus().value() != bootstrapping.cipher_modulus().value()
            || glwe.secret_key_type() != bootstrapping.secret_key_type()
            || glwe.noise_distribution().standard_deviation()
                != bootstrapping.noise_distribution().standard_deviation()
        {
            return Err(TfheParameterError::BootstrappingGlweParametersMismatch);
        }

        if bootstrapping.basis().modulus() != bootstrapping.cipher_modulus().value() {
            return Err(TfheParameterError::BootstrappingBasisModulusMismatch);
        }

        let extracted_dimension = glwe.secret_key_len();
        if key_switching.input_dimension() != extracted_dimension {
            return Err(TfheParameterError::KeySwitchingInputDimensionMismatch {
                expected: extracted_dimension,
                actual: key_switching.input_dimension(),
            });
        }

        if key_switching.output_dimension() != lwe.dimension() {
            return Err(TfheParameterError::KeySwitchingOutputDimensionMismatch {
                expected: lwe.dimension(),
                actual: key_switching.output_dimension(),
            });
        }

        if key_switching.basis().modulus() != bootstrapping.cipher_modulus().value() {
            return Err(TfheParameterError::KeySwitchingBasisModulusMismatch);
        }

        Ok(Self {
            lwe,
            glwe,
            bootstrapping,
            key_switching,
        })
    }

    /// Returns the small-LWE parameters used for input and output ciphertexts.
    #[inline]
    pub fn lwe(&self) -> &LweParameters<T, LM> {
        &self.lwe
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

    /// Returns the LWE key-switching parameters.
    #[inline]
    pub fn key_switching(&self) -> &LweKeySwitchingParameters<T> {
        &self.key_switching
    }

    /// Returns the plaintext modulus shared by LWE ciphertexts and the GLWE
    /// accumulator.
    #[inline]
    pub fn plain_modulus_value(&self) -> T {
        self.lwe.plain_modulus_value()
    }

    /// Decomposes this parameter set into its component parameter objects.
    #[inline]
    pub fn into_parts(self) -> TfheParameterParts<T, LM, GM> {
        (self.lwe, self.glwe, self.bootstrapping, self.key_switching)
    }
}
