use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{GlweSecretKey, LweSecretKey, TfheParameters};

/// The complete client-side secret material for GLWE-based TFHE.
///
/// The GLWE key is kept in coefficient-domain canonical form. Fourier and NTT
/// representations are derived temporarily while generating evaluation keys.
#[derive(Clone)]
pub struct ClientKey<T: FheUint> {
    lwe_secret_key: LweSecretKey<T>,
    glwe_secret_key: GlweSecretKey<T>,
}

impl<T: FheUint> ClientKey<T> {
    /// Creates a client key from its LWE and coefficient-domain GLWE keys.
    #[inline]
    pub fn new(lwe_secret_key: LweSecretKey<T>, glwe_secret_key: GlweSecretKey<T>) -> Self {
        Self {
            lwe_secret_key,
            glwe_secret_key,
        }
    }

    /// Returns the small-LWE secret key.
    #[inline]
    pub fn lwe_secret_key(&self) -> &LweSecretKey<T> {
        &self.lwe_secret_key
    }

    /// Returns the coefficient-domain GLWE secret key.
    #[inline]
    pub fn glwe_secret_key(&self) -> &GlweSecretKey<T> {
        &self.glwe_secret_key
    }

    /// Checks that this key has the shape and distributions required by a
    /// parameter set.
    pub fn check_compatible<LM, GM>(
        &self,
        parameters: &TfheParameters<T, LM, GM>,
    ) -> Result<(), TfheKeyError>
    where
        LM: RingContext<T>,
        GM: RingContext<T>,
    {
        if self.lwe_secret_key.dimension() != parameters.small_lwe().dimension() {
            return Err(TfheKeyError::LweDimensionMismatch {
                expected: parameters.small_lwe().dimension(),
                actual: self.lwe_secret_key.dimension(),
            });
        }
        if self.lwe_secret_key.distr() != parameters.small_lwe().secret_key_type() {
            return Err(TfheKeyError::LweSecretKeyDistributionMismatch);
        }
        if self.glwe_secret_key.dimension() != parameters.glwe().dimension() {
            return Err(TfheKeyError::GlweDimensionMismatch {
                expected: parameters.glwe().dimension(),
                actual: self.glwe_secret_key.dimension(),
            });
        }
        if self.glwe_secret_key.poly_length() != parameters.glwe().poly_length() {
            return Err(TfheKeyError::PolynomialLengthMismatch {
                expected: parameters.glwe().poly_length(),
                actual: self.glwe_secret_key.poly_length(),
            });
        }
        if self.glwe_secret_key.distr() != parameters.glwe().secret_key_type() {
            return Err(TfheKeyError::GlweSecretKeyDistributionMismatch);
        }
        Ok(())
    }

    /// Decomposes this client key into its two secret keys.
    #[inline]
    pub fn into_parts(self) -> (LweSecretKey<T>, GlweSecretKey<T>) {
        (self.lwe_secret_key, self.glwe_secret_key)
    }
}

/// An incompatibility between secret keys and TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// The LWE secret key has the wrong dimension.
    #[error("LWE secret-key dimension mismatch: expected {expected}, got {actual}")]
    LweDimensionMismatch {
        /// Dimension required by the parameters.
        expected: usize,
        /// Dimension found in the key.
        actual: usize,
    },

    /// The LWE secret-key distribution does not match the parameters.
    #[error("LWE secret-key distribution mismatch")]
    LweSecretKeyDistributionMismatch,

    /// The GLWE secret key has the wrong dimension.
    #[error("GLWE secret-key dimension mismatch: expected {expected}, got {actual}")]
    GlweDimensionMismatch {
        /// Dimension required by the parameters.
        expected: usize,
        /// Dimension found in the key.
        actual: usize,
    },

    /// The GLWE secret key has the wrong polynomial length.
    #[error("GLWE polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the parameters.
        expected: usize,
        /// Polynomial length found in the key.
        actual: usize,
    },

    /// The GLWE secret-key distribution does not match the parameters.
    #[error("GLWE secret-key distribution mismatch")]
    GlweSecretKeyDistributionMismatch,
}
