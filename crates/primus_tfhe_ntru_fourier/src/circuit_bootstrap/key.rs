//! Optional trace and scheme-switch material under the accumulator secret.

use primus_fft::{FftTable, TorusFftValue};
use primus_ntru::{FourierNtruSchemeSwitchKey, FourierNtruSecretKey, FourierNtruTraceKey};

use crate::{CircuitBootstrapParameters, ClientKey, KeyGenerationError, KeyGenerator};

/// Additional keys for NTRU CBS; ordinary BR material remains in [`crate::ServerKey`].
/// Both keys use the accumulator secret, not the post-PBS client secret.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`FourierNtruSchemeSwitchKey`].
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    parameters: CircuitBootstrapParameters<T>,
    trace: FourierNtruTraceKey<T>,
    scheme_switch: FourierNtruSchemeSwitchKey<T>,
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

impl<T, Table> KeyGenerator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates the optional trace and scheme-switch keys for a compatible client.
    ///
    /// Checks parameter and client-key compatibility before sampling. The caller
    /// selects the independent noise/decomposition/security budgets described on
    /// [`CircuitBootstrapParameters`]. Actual secret identity must be shared with
    /// the server key later used by the evaluator, as must the FFT table instance.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        if !parameters.is_compatible(self.context.parameters()) {
            return Err(KeyGenerationError::IncompatibleCircuitBootstrapParameters);
        }
        client_key.check_compatible(self.context.parameters())?;
        let secret = client_key.accumulator_ntru_secret_key();
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(secret, &mut self.fft)?;
        Ok(
            self.generate_circuit_bootstrap_key_with_main(
                client_key,
                &transformed,
                parameters,
                rng,
            ),
        )
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        transformed: &FourierNtruSecretKey,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let secret = client_key.accumulator_ntru_secret_key();
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
