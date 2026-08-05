use num_traits::ConstZero;
use primus_integer::FheUint;
use primus_lattice::GlweSize;
use primus_reduce::RingContext;

use crate::{
    GlweSecretKey, LweSecretKey, PbsOrder, SecretCoefficient, SecretKeyDistr, TfheParameters,
};

/// Borrowed coefficients of the LWE secret key used by external TFHE
/// ciphertexts.
#[derive(Clone, Copy)]
pub enum LweSecretKeyRef<'a, T: FheUint> {
    /// Modulus-encoded LWE coefficients.
    Encoded(&'a [T]),
    /// Canonical signed GLWE coefficients viewed as an expanded LWE key.
    Signed(&'a [SecretCoefficient<T>]),
}

impl<T: FheUint> LweSecretKeyRef<'_, T> {
    /// Returns the LWE dimension.
    #[inline]
    pub fn dimension(&self) -> usize {
        match self {
            Self::Encoded(coefficients) => coefficients.len(),
            Self::Signed(coefficients) => coefficients.len(),
        }
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
            PbsOrder::BootstrapKeyswitch => {
                LweSecretKeyRef::Encoded(self.small_lwe_secret_key.as_ref())
            }
            PbsOrder::KeyswitchBootstrap => {
                LweSecretKeyRef::Signed(self.glwe_secret_key.as_slice())
            }
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

    /// Returns the padded GLWE key used as the target of TFHE GLWE key switching.
    ///
    /// The small LWE coefficients occupy the prefix in their natural order;
    /// the remaining coefficients are zero. `parameters` must already have
    /// passed [`Self::check_compatible`].
    pub fn padded_small_glwe_secret_key<LM, GM>(
        &self,
        parameters: &TfheParameters<T, LM, GM>,
    ) -> GlweSecretKey<T>
    where
        LM: RingContext<T>,
        GM: RingContext<T>,
    {
        let lwe_secret_key = &self.small_lwe_secret_key;
        let lwe_dimension = lwe_secret_key.dimension();
        let poly_length = parameters.glwe().poly_length();
        let capacity = lwe_dimension
            .checked_next_multiple_of(poly_length)
            .expect("validated TFHE dimensions must fit in usize");

        let mut key = vec![SecretCoefficient::<T>::ZERO; capacity];
        let distribution = match lwe_secret_key.distr() {
            SecretKeyDistr::Binary => {
                key[..lwe_dimension]
                    .iter_mut()
                    .zip(lwe_secret_key.as_ref())
                    .for_each(|(output, &coefficient)| {
                        *output = coefficient.cast_to_signed();
                    });
                SecretKeyDistr::Binary
            }
            SecretKeyDistr::Ternary => {
                let minus_one = parameters.small_lwe().cipher_modulus_minus_one();
                key[..lwe_dimension]
                    .iter_mut()
                    .zip(lwe_secret_key.as_ref())
                    .for_each(|(output, &coefficient)| {
                        *output = if coefficient == minus_one {
                            -T::ONE.cast_to_signed()
                        } else {
                            coefficient.cast_to_signed()
                        };
                    });
                SecretKeyDistr::Ternary
            }
            SecretKeyDistr::Gaussian(_) => {
                panic!("TFHE small LWE secret keys must use the binary distribution")
            }
        };

        GlweSecretKey::new(
            key,
            GlweSize::new(capacity / poly_length, poly_length),
            distribution,
        )
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
        if self.small_lwe_secret_key.distr() != parameters.small_lwe().secret_key_distr() {
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
        if self.glwe_secret_key.distr() != parameters.glwe().secret_key_distr() {
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
