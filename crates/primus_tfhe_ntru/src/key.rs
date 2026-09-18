use num_traits::{ConstOne, ConstZero};
use primus_integer::FheUint;
use primus_ntru::NtruSecretKey;
use primus_reduce::RingContext;
use primus_tfhe::LweSecretKeyRef;

use crate::{TfheKeyError, TfheParameters};

/// Coefficient-domain client and accumulator secrets for NTRU TFHE.
#[derive(Clone)]
pub struct ClientKey<T: FheUint> {
    client_ntru_secret_key: NtruSecretKey<T>,
    accumulator_ntru_secret_key: NtruSecretKey<T>,
    external_lwe_dimension: usize,
}

impl<T: FheUint> ClientKey<T> {
    /// Imports the two coefficient-domain NTRU secrets.
    ///
    /// This constructor only checks that the external LWE dimension fits in
    /// the client key. Binding the imported key to TFHE parameters must call
    /// [`Self::check_compatible`] to validate its distributions, binary prefix,
    /// and zero padding before use.
    ///
    /// # Panics
    ///
    /// Panics unless the external LWE dimension belongs to the client NTRU
    /// polynomial.
    #[must_use]
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

    /// Returns the client NTRU key used by external LWE ciphertexts.
    #[must_use]
    #[inline]
    pub fn client_ntru_secret_key(&self) -> &NtruSecretKey<T> {
        &self.client_ntru_secret_key
    }

    /// Returns the accumulator NTRU key used during blind rotation.
    #[must_use]
    #[inline]
    pub fn accumulator_ntru_secret_key(&self) -> &NtruSecretKey<T> {
        &self.accumulator_ntru_secret_key
    }

    /// Returns the active prefix used as the external LWE key.
    ///
    /// [`Self::check_compatible`] verifies that imported coefficients are binary.
    #[must_use]
    #[inline]
    pub fn external_lwe_secret_coefficients(&self) -> &[T::SignedInteger] {
        &self.client_ntru_secret_key.as_slice()[..self.external_lwe_dimension]
    }

    /// Returns the number of active coefficients in the padded client key.
    #[must_use]
    #[inline]
    pub fn external_lwe_dimension(&self) -> usize {
        self.external_lwe_dimension
    }

    /// Returns the client NTRU coefficients as the external LWE key.
    #[must_use]
    #[inline]
    pub fn external_lwe_secret_key(&self) -> LweSecretKeyRef<'_, T> {
        LweSecretKeyRef::Signed(self.external_lwe_secret_coefficients())
    }

    /// Generates an LWE public key under the binary client coefficient prefix.
    ///
    /// Borrows only the active external LWE secret and uses `external_lwe`'s
    /// noise sampler for public-key generation. Public-key storage contains
    /// `n * (n + 1)` coefficients, excluding the client's zero padding.
    ///
    /// # Correctness
    ///
    /// Public-key usage follows [`crate::EncryptionKey`]'s noise and key-identity
    /// contracts and [`crate::LwePublicKey`]'s security requirements.
    ///
    /// # Panics
    ///
    /// Panics if the public-key storage length overflows `usize`.
    pub fn try_generate_public_key<M, R>(
        &self,
        parameters: &TfheParameters<T, M>,
        rng: &mut R,
    ) -> Result<crate::LwePublicKey<T>, TfheKeyError>
    where
        M: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_compatible(parameters)?;
        Ok(crate::LwePublicKey::generate(
            self.external_lwe_secret_key(),
            parameters.external_lwe(),
            rng,
        ))
    }

    /// Validates an imported key before binding it to TFHE parameters.
    ///
    /// Besides shapes and distribution labels, this checks the actual client
    /// coefficients: the active prefix must contain only zero and one, and
    /// the remaining coefficients must be zero. NTRU distribution labels alone
    /// do not establish the binary control values required by blind rotation.
    pub fn check_compatible<M>(&self, parameters: &TfheParameters<T, M>) -> Result<(), TfheKeyError>
    where
        M: RingContext<T>,
    {
        let expected = parameters.poly_length();
        if self.client_ntru_secret_key.poly_length() != expected
            || self.accumulator_ntru_secret_key.poly_length() != expected
        {
            return Err(TfheKeyError::PolynomialLengthMismatch);
        }
        if self.client_ntru_secret_key.distr()
            != parameters.ntru_key_switching().ntru().secret_key_distr()
        {
            return Err(TfheKeyError::ClientSecretKeyDistributionMismatch);
        }
        let expected_lwe_dimension = parameters.external_lwe_dimension();
        if self.external_lwe_dimension != expected_lwe_dimension {
            return Err(TfheKeyError::ExternalLweDimensionMismatch);
        }
        let (active, padding) = self
            .client_ntru_secret_key
            .as_slice()
            .split_at(self.external_lwe_dimension);
        // Aggregate both complete slices before inspecting the result, so
        // rejection does not stop at the first invalid secret coefficient.
        let active_bits = active
            .iter()
            .fold(T::SignedInteger::ZERO, |bits, &coefficient| {
                bits | coefficient
            });
        let padding_bits = padding
            .iter()
            .fold(T::SignedInteger::ZERO, |bits, &coefficient| {
                bits | coefficient
            });
        if active_bits & !T::SignedInteger::ONE != T::SignedInteger::ZERO {
            return Err(TfheKeyError::ClientSecretKeyMustBeBinary);
        }
        if padding_bits != T::SignedInteger::ZERO {
            return Err(TfheKeyError::ClientSecretKeyPaddingMismatch);
        }
        if self.accumulator_ntru_secret_key.distr()
            != parameters.accumulator_ntru().secret_key_distr()
        {
            return Err(TfheKeyError::AccumulatorSecretKeyDistributionMismatch);
        }
        Ok(())
    }

    /// Decomposes the client key into client and accumulator NTRU secrets.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (NtruSecretKey<T>, NtruSecretKey<T>, usize) {
        (
            self.client_ntru_secret_key,
            self.accumulator_ntru_secret_key,
            self.external_lwe_dimension,
        )
    }
}
