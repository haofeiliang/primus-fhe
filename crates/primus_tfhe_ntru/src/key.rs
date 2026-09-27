use primus_integer::{FheUint, SignedInteger};
use primus_ntru::NtruSecretKey;
use primus_reduce::RingContext;

use crate::{TfheKeyError, TfheParameters};

/// Coefficient-domain client and accumulator secrets for NTRU TFHE.
#[derive(Clone)]
pub struct ClientKey<T: FheUint> {
    external_lwe_secret_key: primus_lwe::LweSecretKey<T>,
    accumulator_ntru_secret_key: NtruSecretKey<T>,
}

impl<T: FheUint> ClientKey<T> {
    /// Imports independent external LWE and accumulator NTRU secrets.
    /// Binding to parameters validates dimensions, distribution labels and external residues.
    #[must_use]
    pub fn new(
        external_lwe_secret_key: primus_lwe::LweSecretKey<T>,
        accumulator_ntru_secret_key: NtruSecretKey<T>,
    ) -> Self {
        Self {
            external_lwe_secret_key,
            accumulator_ntru_secret_key,
        }
    }

    /// Returns the accumulator NTRU key used during blind rotation.
    #[must_use]
    #[inline]
    pub fn accumulator_ntru_secret_key(&self) -> &NtruSecretKey<T> {
        &self.accumulator_ntru_secret_key
    }

    /// Returns the independent external LWE secret, encoded at external modulus q.
    #[must_use]
    pub fn external_lwe_secret_key(&self) -> &primus_lwe::LweSecretKey<T> {
        &self.external_lwe_secret_key
    }

    /// Returns the external LWE dimension.
    #[must_use]
    pub fn external_lwe_dimension(&self) -> usize {
        self.external_lwe_secret_key.dimension()
    }

    /// Generates an LWE public key under the external secret.
    ///
    /// Borrows only the external LWE secret and uses `external_lwe`'s
    /// noise sampler for public-key generation. Public-key storage contains
    /// `n * (n + 1)` coefficients.
    ///
    /// # Correctness
    ///
    /// Public-key usage follows [`crate::EncryptionKey`]'s noise and key-identity
    /// contracts and [`crate::LwePublicKey`]'s security requirements.
    ///
    /// # Panics
    ///
    /// Panics if the public-key storage length overflows `usize`.
    pub fn try_generate_public_key<M, LM, R>(
        &self,
        parameters: &TfheParameters<T, M, LM>,
        rng: &mut R,
    ) -> Result<crate::LwePublicKey<T>, TfheKeyError>
    where
        M: RingContext<T>,
        LM: RingContext<T>,
        R: rand::Rng + rand::CryptoRng,
    {
        self.check_compatible(parameters)?;
        Ok(crate::LwePublicKey::generate(
            self.external_lwe_secret_key().as_view(),
            parameters.external_lwe(),
            rng,
        ))
    }

    /// Checks shapes, distribution labels and canonical binary/ternary external residues.
    /// Accumulator coefficients must have magnitude below an explicit external q.
    /// Accumulator invertibility is checked by the backend when preparing its secret.
    pub fn check_compatible<M: RingContext<T>, LM: RingContext<T>>(
        &self,
        parameters: &TfheParameters<T, M, LM>,
    ) -> Result<(), TfheKeyError> {
        if self.accumulator_ntru_secret_key.poly_length() != parameters.poly_length() {
            return Err(TfheKeyError::PolynomialLengthMismatch);
        }
        let external = parameters.external_lwe();
        if self.external_lwe_secret_key.distr() != external.secret_key_distr() {
            return Err(TfheKeyError::ClientSecretKeyDistributionMismatch);
        }
        if self.external_lwe_dimension() != external.dimension() {
            return Err(TfheKeyError::ExternalLweDimensionMismatch);
        }
        let ternary = external.secret_key_distr().is_ternary();
        let minus_one = external.cipher_modulus_minus_one();
        // Visit all coefficients; do not stop at the first invalid secret value.
        let invalid = self
            .external_lwe_secret_key
            .as_ref()
            .iter()
            .fold(false, |invalid, &x| {
                invalid | !((x == T::ZERO) | (x == T::ONE) | (ternary & (x == minus_one)))
            });
        if invalid {
            return Err(TfheKeyError::InvalidClientSecretKeyCoefficient);
        }
        if self.accumulator_ntru_secret_key.distr()
            != parameters.accumulator_ntru().secret_key_distr()
        {
            return Err(TfheKeyError::AccumulatorSecretKeyDistributionMismatch);
        }
        if let Some(q) = external.cipher_modulus_value() {
            let too_large = self
                .accumulator_ntru_secret_key
                .as_slice()
                .iter()
                .fold(false, |invalid, &s| invalid | (s.unsigned_abs() >= q));
            if too_large {
                return Err(TfheKeyError::AccumulatorSecretOutsideLweModulus);
            }
        }
        Ok(())
    }

    /// Decomposes the key into independent external LWE and accumulator NTRU secrets.
    #[must_use]
    pub fn into_parts(self) -> (primus_lwe::LweSecretKey<T>, NtruSecretKey<T>) {
        (
            self.external_lwe_secret_key,
            self.accumulator_ntru_secret_key,
        )
    }
}
