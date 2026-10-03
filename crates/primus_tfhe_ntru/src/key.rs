use primus_integer::{FheUint, SignedInteger};
use primus_ntru::NtruSecretKey;
use primus_reduce::RingContext;

use crate::{TfheKeyError, TfheParameters};

/// Independent external LWE and accumulator NTRU secrets for TFHE setup.
/// Ordinary clients need only [`Self::external_lwe_secret_key`]; ring clients
/// need only [`Self::accumulator_ntru_secret_key`]. [`Self::into_parts`] separates
/// the owners without copying secret buffers.
#[derive(Clone)]
pub struct ClientKey<T: FheUint> {
    external_lwe_secret_key: primus_lwe::LweSecretKey<T>,
    accumulator_ntru_secret_key: NtruSecretKey<T>,
}

impl<T: FheUint> ClientKey<T> {
    /// Imports independent external LWE and accumulator NTRU secrets.
    /// [`Self::check_compatible`] validates the full setup before evaluation-key
    /// generation. Ordinary client binding checks only the selected secret.
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

    /// Returns the actual external secret storage dimension.
    /// Imported keys may have dimension zero until bound to checked parameters.
    #[must_use]
    pub fn external_lwe_dimension(&self) -> usize {
        self.external_lwe_secret_key.dimension()
    }

    /// Checks the full setup bundle before generating PBS or return material.
    /// Validates shapes, the recorded LWE modulus, distribution labels and canonical
    /// binary/ternary external residues before borrowing raw key views.
    /// Accumulator coefficients must have magnitude below an explicit external q.
    /// Accumulator invertibility is checked by the backend when preparing its secret.
    pub fn check_compatible<M: RingContext<T>, LM: RingContext<T>>(
        &self,
        parameters: &TfheParameters<T, M, LM>,
    ) -> Result<(), TfheKeyError> {
        self.check_blind_rotation_compatible(parameters)?;
        if let Some(q) = parameters.external_lwe().cipher_modulus_value() {
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

    /// Checks the two secret roles used by blind-rotation generation.
    /// Unlike full PBS setup, this does not require f to fit the return modulus q.
    /// Backend conversion still owns the accumulator's representation requirements.
    pub fn check_blind_rotation_compatible<M: RingContext<T>, LM: RingContext<T>>(
        &self,
        parameters: &TfheParameters<T, M, LM>,
    ) -> Result<(), TfheKeyError> {
        parameters.check_external_secret_key(&self.external_lwe_secret_key)?;
        parameters.check_accumulator_secret_key(&self.accumulator_ntru_secret_key)
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

impl<T: FheUint, M: RingContext<T>, LM: RingContext<T>> TfheParameters<T, M, LM> {
    /// Generates only the Q→q, f→s return material, with no transform workspace.
    /// Checks the full secret pair including the magnitude of f at external q.
    /// Independent BR/CBS material must use the same actual secrets; layout and
    /// modulus checks cannot establish identity or an adequate noise budget.
    pub fn try_generate_lwe_return_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<primus_ntru::NtruLweKeySwitchingKey<T>, TfheKeyError> {
        client_key.check_compatible(self)?;
        Ok(primus_ntru::NtruLweKeySwitchingKey::generate(
            client_key.accumulator_ntru_secret_key(),
            self.accumulator_ntru().cipher_modulus(),
            client_key.external_lwe_secret_key(),
            self.key_switching_lwe(),
            self.key_switching_basis().clone(),
            rng,
        ))
    }

    /// Checks return geometry, source Q and the complete target-q decomposition.
    /// This does not prove source/target secret identity. Call once when composing
    /// an evaluator with independently generated return material.
    pub fn check_lwe_return_key(
        &self,
        key: &primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Result<(), primus_tfhe::TfheEvaluationError> {
        if key.poly_length() != self.poly_length().get()
            || key.input_modulus() != self.accumulator_ntru().cipher_modulus_value()
            || key.output_dimension() != self.external_lwe_dimension()
            || key.basis() != self.key_switching_basis()
        {
            return Err(primus_tfhe::TfheEvaluationError::IncompatibleLweReturnKey);
        }
        Ok(())
    }

    /// Checks only the external LWE owner before borrowing its encoded view.
    pub(crate) fn check_external_secret_key(
        &self,
        key: &primus_lwe::LweSecretKey<T>,
    ) -> Result<(), TfheKeyError> {
        let external = self.external_lwe();
        if key.cipher_modulus_minus_one() != external.cipher_modulus_minus_one() {
            return Err(TfheKeyError::LweSecretKeyModulusMismatch);
        }
        if key.distr() != external.secret_key_distr() {
            return Err(TfheKeyError::ClientSecretKeyDistributionMismatch);
        }
        if key.dimension() != external.dimension().get() {
            return Err(TfheKeyError::ExternalLweDimensionMismatch);
        }
        let ternary = external.secret_key_distr().is_ternary();
        let minus_one = external.cipher_modulus_minus_one();
        // Visit all coefficients; do not stop at the first invalid secret value.
        let invalid = key.as_ref().iter().fold(false, |invalid, &x| {
            invalid | !((x == T::ZERO) | (x == T::ONE) | (ternary & (x == minus_one)))
        });
        if invalid {
            return Err(TfheKeyError::InvalidClientSecretKeyCoefficient);
        }
        Ok(())
    }

    /// Checks only the accumulator secret's ring length and distribution label.
    /// Backend conversion establishes invertibility; signed coefficient magnitudes
    /// remain its caller precondition. Return-key compatibility with external q
    /// belongs to full setup and is not needed by an accumulator client.
    pub fn check_accumulator_secret_key(&self, key: &NtruSecretKey<T>) -> Result<(), TfheKeyError> {
        if key.poly_length() != self.poly_length().get() {
            return Err(TfheKeyError::PolynomialLengthMismatch);
        }
        if key.distr() != self.accumulator_ntru().secret_key_distr() {
            return Err(TfheKeyError::AccumulatorSecretKeyDistributionMismatch);
        }
        Ok(())
    }
}
