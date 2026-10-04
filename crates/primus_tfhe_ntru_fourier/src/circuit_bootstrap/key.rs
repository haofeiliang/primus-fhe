//! Optional trace and scheme-switch material under the accumulator secret.

use primus_fft::{FftTable, TorusFftValue};
use primus_ntru::{FourierNtruSchemeSwitchKey, FourierNtruSecretKey, FourierNtruTraceKey};

use crate::{CircuitBootstrapParameters, KeyGenerationError, KeyGenerator, TfheContext};

/// Additional keys for NTRU CBS; ordinary BR material is owned by [`crate::BlindRotationKey`].
/// Both keys use the accumulator secret, not the post-PBS client secret.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`FourierNtruSchemeSwitchKey`].
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    parameters: CircuitBootstrapParameters<T>,
    trace: FourierNtruTraceKey<T>,
    scheme_switch: FourierNtruSchemeSwitchKey<T>,
}

// Validated CBS material and its complete output basis. BR controls belong to
// the shared resources; NTRU scheme switching cannot substitute another basis.
pub(super) struct CircuitBootstrapBinding<'a, T: TorusFftValue> {
    pub(super) key: &'a CircuitBootstrapKey<T>,
    pub(super) parameters: &'a CircuitBootstrapParameters<T>,
}

impl<'a, T: TorusFftValue> CircuitBootstrapBinding<'a, T> {
    // Check CBS parameters before online use; both BR algorithms produce the
    // same accumulator representation for trace and scheme switching.
    // Receiving material and checking its geometry do not prove actual key identity.
    pub(super) fn try_new<LM: primus_reduce::RingContext<T>>(
        tfhe: &crate::TfheParameters<T, LM>,
        key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, crate::TfheEvaluationError> {
        let parameters = key.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        Ok(Self { key, parameters })
    }
}

impl<T: TorusFftValue> CircuitBootstrapKey<T> {
    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CircuitBootstrapParameters<T> {
        &self.parameters
    }

    /// Returns the reverse-trace projection key under f_acc.
    #[must_use]
    pub fn trace_key(&self) -> &FourierNtruTraceKey<T> {
        &self.trace
    }

    /// Returns the NLev-to-NGSW key under f_acc.
    #[must_use]
    pub fn scheme_switch_key(&self) -> &FourierNtruSchemeSwitchKey<T> {
        &self.scheme_switch
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates the optional trace and scheme-switch keys from only the accumulator secret.
    ///
    /// Checks parameters and the accumulator layout/distribution before sampling. The caller
    /// selects the independent noise/decomposition/security budgets described on
    /// [`CircuitBootstrapParameters`]. Actual secret identity must be shared with
    /// the server key later used by the evaluator, as must the FFT table instance.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        if !parameters.is_compatible(self.context.parameters()) {
            return Err(KeyGenerationError::IncompatibleCircuitBootstrapParameters);
        }
        self.context
            .parameters()
            .check_accumulator_secret_key(secret)?;
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(secret, &mut self.fft)?;
        Ok(self.generate_circuit_bootstrap_key_with_main(secret, &transformed, parameters, rng))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        transformed: &FourierNtruSecretKey,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let trace = FourierNtruTraceKey::generate(
            secret,
            transformed,
            parameters.trace(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        let scheme_switch = FourierNtruSchemeSwitchKey::generate(
            secret,
            transformed,
            parameters.output_basis(),
            parameters.scheme_switch(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        CircuitBootstrapKey {
            parameters,
            trace,
            scheme_switch,
        }
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates optional CBS material under this client's accumulator secret.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_key`]'s contracts.
    pub fn try_generate_circuit_bootstrap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        secret: &primus_ntru::NtruSecretKey<T>,
        parameters: crate::CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<crate::CircuitBootstrapKey<T>, crate::KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_key(secret, parameters, rng)
    }
}
