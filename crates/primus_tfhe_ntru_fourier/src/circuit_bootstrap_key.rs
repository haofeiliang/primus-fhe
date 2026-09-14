//! Optional trace and scheme-switch material under the accumulator secret.

use primus_fft::{FftTable, TorusFftValue};
use primus_ntru::{FourierNtruSchemeSwitchKey, FourierNtruSecretKey, FourierNtruTraceKey};

use crate::{CircuitBootstrapParameters, ClientKey, KeyGenerator, TfheKeyError};

/// Failure while generating optional circuit-bootstrap material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapKeyError {
    /// The CBS parameters belong to a different accumulator or input domain.
    #[error("circuit-bootstrap parameters do not match this TFHE context")]
    IncompatibleParameters,
    /// The supplied client key is incompatible or cannot be transformed.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
}

/// Additional keys for NTRU CBS; ordinary BR material remains in [`crate::ServerKey`].
/// Both keys use the accumulator secret, not the post-PBS client secret.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`FourierNtruSchemeSwitchKey`].
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    trace: FourierNtruTraceKey<T>,
    scheme_switch: FourierNtruSchemeSwitchKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapKey<T> {
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

    pub(crate) fn is_compatible(&self, parameters: &CircuitBootstrapParameters<T>) -> bool {
        self.trace.poly_length() == parameters.trace().poly_length()
            && self.trace.basis() == parameters.trace().basis()
            && self.scheme_switch.poly_length() == parameters.output().poly_length()
            && self.scheme_switch.key_basis() == parameters.scheme_switch().basis()
            && self.scheme_switch.output_basis() == parameters.output().basis()
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
        parameters: &CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, CircuitBootstrapKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        if !parameters.is_compatible(self.context.parameters()) {
            return Err(CircuitBootstrapKeyError::IncompatibleParameters);
        }
        client_key
            .check_compatible(self.context.parameters())
            .map_err(TfheKeyError::from)?;
        let secret = client_key.accumulator_ntru_secret_key();
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(secret, &mut self.fft)
            .map_err(TfheKeyError::from)?;
        let trace = FourierNtruTraceKey::generate(
            secret,
            &transformed,
            parameters.trace(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        let scheme_switch = FourierNtruSchemeSwitchKey::generate(
            secret,
            &transformed,
            parameters.output().basis(),
            parameters.scheme_switch(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );
        Ok(CircuitBootstrapKey {
            trace,
            scheme_switch,
        })
    }
}
