use primus_integer::FheUint;
use primus_reduce::RingContext;

use crate::{GlweSecretKey, LweSecretKey, PbsOrder, TfheParameters};

/// Borrowed coefficients of the LWE secret key used by external TFHE
/// ciphertexts.
#[derive(Clone, Copy)]
pub struct LweSecretKeyRef<'a, T: FheUint>(&'a [T]);

impl<T: FheUint> LweSecretKeyRef<'_, T> {
    /// Returns the LWE dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        self.0.len()
    }

    /// Returns the secret-key coefficients.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        self.0
    }
}

impl<T: FheUint> AsRef<[T]> for LweSecretKeyRef<'_, T> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        self.0
    }
}

/// The complete client-side secret material for GLWE-based TFHE.
///
/// The GLWE key is kept in coefficient-domain canonical form. Fourier and NTT
/// representations are derived temporarily while generating evaluation keys.
#[derive(Clone)]
pub struct ClientKey<T: FheUint> {
    small_lwe_secret_key: LweSecretKey<T>,
    glwe_secret_key: GlweSecretKey<T>,
    pbs_order: PbsOrder,
}

impl<T: FheUint> ClientKey<T> {
    /// Creates a client key from its LWE and coefficient-domain GLWE keys.
    #[inline]
    pub fn new(
        small_lwe_secret_key: LweSecretKey<T>,
        glwe_secret_key: GlweSecretKey<T>,
        pbs_order: PbsOrder,
    ) -> Self {
        Self {
            small_lwe_secret_key,
            glwe_secret_key,
            pbs_order,
        }
    }

    /// Returns the secret key used by external LWE ciphertexts.
    ///
    /// Bootstrap-then-key-switch uses the small-LWE key. Key-switch-then-
    /// bootstrap uses the coefficient expansion of the GLWE key.
    #[inline]
    pub fn lwe_secret_key(&self) -> LweSecretKeyRef<'_, T> {
        match self.pbs_order {
            PbsOrder::BootstrapKeyswitch => LweSecretKeyRef(self.small_lwe_secret_key.as_ref()),
            PbsOrder::KeyswitchBootstrap => LweSecretKeyRef(self.glwe_secret_key.as_slice()),
        }
    }

    /// Returns the small-LWE secret key used by the bootstrapping key.
    #[inline]
    pub fn small_lwe_secret_key(&self) -> &LweSecretKey<T> {
        &self.small_lwe_secret_key
    }

    /// Returns the coefficient-domain GLWE secret key.
    #[inline]
    pub fn glwe_secret_key(&self) -> &GlweSecretKey<T> {
        &self.glwe_secret_key
    }

    /// Returns the PBS order that determines the external LWE key.
    #[inline]
    pub fn pbs_order(&self) -> PbsOrder {
        self.pbs_order
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
        if self.pbs_order != parameters.pbs_order() {
            return Err(TfheKeyError::PbsOrderMismatch {
                expected: parameters.pbs_order(),
                actual: self.pbs_order,
            });
        }
        if self.small_lwe_secret_key.dimension() != parameters.small_lwe().dimension() {
            return Err(TfheKeyError::LweDimensionMismatch {
                expected: parameters.small_lwe().dimension(),
                actual: self.small_lwe_secret_key.dimension(),
            });
        }
        if self.small_lwe_secret_key.distr() != parameters.small_lwe().secret_key_type() {
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
    pub fn into_parts(self) -> (LweSecretKey<T>, GlweSecretKey<T>, PbsOrder) {
        (
            self.small_lwe_secret_key,
            self.glwe_secret_key,
            self.pbs_order,
        )
    }
}

/// An incompatibility between secret keys and TFHE parameters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheKeyError {
    /// The client key was created for a different PBS order.
    #[error("PBS order mismatch: expected {expected:?}, got {actual:?}")]
    PbsOrderMismatch {
        /// PBS order required by the parameters.
        expected: PbsOrder,
        /// PBS order associated with the client key.
        actual: PbsOrder,
    },

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
