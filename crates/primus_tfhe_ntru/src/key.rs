use num_traits::ConstZero;
use primus_integer::FheUint;
use primus_ntru::NtruSecretKey;
use primus_reduce::RingContext;
use primus_tfhe::LweSecretKeyRef;

use crate::NtruTfheParameters;

/// Coefficient-domain client and accumulator secrets for NTRU TFHE.
#[derive(Clone)]
pub struct NtruClientKey<T: FheUint> {
    client_ntru_secret_key: NtruSecretKey<T>,
    accumulator_ntru_secret_key: NtruSecretKey<T>,
    external_lwe_dimension: usize,
}

impl<T: FheUint> NtruClientKey<T> {
    /// Creates a client key from the two coefficient-domain NTRU secrets.
    ///
    /// # Panics
    ///
    /// Panics unless the external LWE dimension belongs to the client NTRU
    /// polynomial.
    #[inline]
    pub fn new(
        client_ntru_secret_key: NtruSecretKey<T>,
        accumulator_ntru_secret_key: NtruSecretKey<T>,
        external_lwe_dimension: usize,
    ) -> Self {
        assert!(
            (1..=client_ntru_secret_key.poly_length()).contains(&external_lwe_dimension),
            "external LWE dimension must fit in the client NTRU key"
        );
        Self {
            client_ntru_secret_key,
            accumulator_ntru_secret_key,
            external_lwe_dimension,
        }
    }

    /// Returns the binary client NTRU key used by external LWE ciphertexts.
    #[inline]
    pub fn client_ntru_secret_key(&self) -> &NtruSecretKey<T> {
        &self.client_ntru_secret_key
    }

    /// Returns the accumulator NTRU key used during blind rotation.
    #[inline]
    pub fn accumulator_ntru_secret_key(&self) -> &NtruSecretKey<T> {
        &self.accumulator_ntru_secret_key
    }

    /// Returns the active binary prefix used as the external LWE key.
    #[inline]
    pub fn external_lwe_secret_key(&self) -> &[primus_fhe_core::SecretCoefficient<T>] {
        &self.client_ntru_secret_key.as_slice()[..self.external_lwe_dimension]
    }

    /// Returns the number of active coefficients in the padded client key.
    #[inline]
    pub fn external_lwe_dimension(&self) -> usize {
        self.external_lwe_dimension
    }

    /// Returns the client NTRU coefficients as the external LWE key.
    #[inline]
    pub fn lwe_secret_key(&self) -> LweSecretKeyRef<'_, T> {
        LweSecretKeyRef::Signed(self.external_lwe_secret_key())
    }

    /// Checks the two secret-key shapes and distributions against parameters.
    pub fn check_compatible<M>(
        &self,
        parameters: &NtruTfheParameters<T, M>,
    ) -> Result<(), NtruKeyError>
    where
        M: RingContext<T>,
    {
        let expected = parameters.poly_length();
        if self.client_ntru_secret_key.poly_length() != expected
            || self.accumulator_ntru_secret_key.poly_length() != expected
        {
            return Err(NtruKeyError::PolynomialLengthMismatch);
        }
        if self.client_ntru_secret_key.distr()
            != parameters.key_switching().ntru().secret_key_distr()
        {
            return Err(NtruKeyError::ClientSecretKeyDistributionMismatch);
        }
        let expected_lwe_dimension = parameters.external_lwe().dimension();
        if self.external_lwe_dimension != expected_lwe_dimension {
            return Err(NtruKeyError::ExternalLweDimensionMismatch);
        }
        if self.client_ntru_secret_key.as_slice()[self.external_lwe_dimension..]
            .iter()
            .any(|&coefficient| coefficient != primus_fhe_core::SecretCoefficient::<T>::ZERO)
        {
            return Err(NtruKeyError::ClientSecretKeyPaddingMismatch);
        }
        if self.accumulator_ntru_secret_key.distr()
            != parameters.bootstrapping().ntru().secret_key_distr()
        {
            return Err(NtruKeyError::AccumulatorSecretKeyDistributionMismatch);
        }
        Ok(())
    }

    /// Decomposes the client key into client and accumulator NTRU secrets.
    #[inline]
    pub fn into_parts(self) -> (NtruSecretKey<T>, NtruSecretKey<T>, usize) {
        (
            self.client_ntru_secret_key,
            self.accumulator_ntru_secret_key,
            self.external_lwe_dimension,
        )
    }
}

/// An incompatibility between NTRU TFHE parameters and client keys.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NtruKeyError {
    /// At least one NTRU secret has the wrong polynomial length.
    #[error("NTRU client-key polynomial length mismatch")]
    PolynomialLengthMismatch,
    /// The client NTRU secret was sampled from a different binary distribution.
    #[error("NTRU client secret-key distribution mismatch")]
    ClientSecretKeyDistributionMismatch,
    /// The active client-key prefix has the wrong LWE dimension.
    #[error("NTRU client key has the wrong external LWE dimension")]
    ExternalLweDimensionMismatch,
    /// At least one coefficient after the active LWE prefix is nonzero.
    #[error("NTRU client key has a nonzero coefficient in its padded suffix")]
    ClientSecretKeyPaddingMismatch,
    /// The accumulator key distribution differs from its parameter set.
    #[error("NTRU accumulator secret-key distribution mismatch")]
    AccumulatorSecretKeyDistributionMismatch,
}
