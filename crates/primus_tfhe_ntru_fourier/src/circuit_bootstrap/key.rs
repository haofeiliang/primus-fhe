//! Optional trace and scheme-switch material under the accumulator secret.

use primus_fft::{FftTable, TorusFftValue};
use primus_ntru::{FourierNtruSchemeSwitchKey, FourierNtruSecretKey, FourierNtruTraceKey};

use crate::{CbsParameters, KeyGenerationError, KeyGenerator, TfheContext};

/// Additional keys for NTRU CBS; ordinary BR material is owned by [`crate::BlindRotationKey`].
/// Both keys use the accumulator secret, not the post-PBS client secret.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`FourierNtruSchemeSwitchKey`].
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    parameters: CbsParameters<T>,
    trace: FourierNtruTraceKey<T>,
    scheme_switch: FourierNtruSchemeSwitchKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapKey<T> {
    /// Checks the key's fixed CBS parameters before preparing LUTs or buffers.
    /// NTRU cannot substitute a different output basis; compatibility does not
    /// establish actual secret or transform identity.
    pub(super) fn check_parameters<LM: primus_reduce::RingContext<T>>(
        &self,
        tfhe: &crate::PbsParameters<T, LM>,
    ) -> Result<(), crate::TfheEvaluationError> {
        if !self.parameters.is_compatible(tfhe) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        Ok(())
    }

    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CbsParameters<T> {
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
    /// selects the CBS decomposition and noise/security budgets described on
    /// [`CbsParameters`]. Actual secret identity must be shared with
    /// the server key later used by the evaluator, as must the FFT table instance.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        parameters: CbsParameters<T>,
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
        parameters: CbsParameters<T>,
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
        parameters: crate::CbsParameters<T>,
        rng: &mut R,
    ) -> Result<crate::CircuitBootstrapKey<T>, crate::KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_key(secret, parameters, rng)
    }
}
