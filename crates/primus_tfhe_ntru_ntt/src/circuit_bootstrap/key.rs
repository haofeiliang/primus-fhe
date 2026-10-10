//! Optional trace and scheme-switch material under the accumulator secret.

use primus_integer::FheUint;
use primus_ntru::{NttNtruSchemeSwitchKey, NttNtruSecretKey, NttNtruTraceKey};
use primus_ntt::MonomialNttTable;

use crate::{
    KeyGenerationError, KeyGenerator, TfheContext, circuit_bootstrap::CbsGadgetParameters,
};

/// Additional keys for NTRU CBS; ordinary BR material is owned by [`crate::key::BlindRotationKey`].
/// Both keys use the accumulator secret, not the post-PBS client secret.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`NttNtruSchemeSwitchKey`].
pub struct CircuitBootstrapKey<T: FheUint> {
    parameters: CbsGadgetParameters<T>,
    trace: NttNtruTraceKey<T>,
    scheme_switch: NttNtruSchemeSwitchKey<T>,
}

impl<T: FheUint> CircuitBootstrapKey<T> {
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

    /// Matches the configured gadget decomposition; the evaluator separately
    /// validates its accumulator domain. NTRU scheme switching fixes the output basis.
    pub(crate) fn is_compatible(&self, parameters: &CbsGadgetParameters<T>) -> bool {
        self.parameters.output_basis() == parameters.output_basis()
            && self.parameters.trace().basis() == parameters.trace().basis()
            && self.parameters.scheme_switch().basis() == parameters.scheme_switch().basis()
    }

    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CbsGadgetParameters<T> {
        &self.parameters
    }

    /// Returns the reverse-trace projection key under f_acc.
    #[must_use]
    pub fn trace_key(&self) -> &NttNtruTraceKey<T> {
        &self.trace
    }

    /// Returns the NLev-to-NGSW key under f_acc.
    #[must_use]
    pub fn scheme_switch_key(&self) -> &NttNtruSchemeSwitchKey<T> {
        &self.scheme_switch
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates the optional trace and scheme-switch keys from only the accumulator secret.
    ///
    /// Checks parameters and the accumulator layout/distribution before sampling. The caller
    /// selects the CBS decomposition and noise/security budgets described on
    /// [`CbsGadgetParameters`]. Actual secret identity must be shared with
    /// the server key later used by the evaluator.
    /// Accumulator coefficients inherit
    /// [`NttNtruSecretKey::try_from_coeff_secret_key`]'s magnitude bound.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        parameters: CbsGadgetParameters<T>,
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
        let transformed = NttNtruSecretKey::try_from_coeff_secret_key(
            secret,
            parameters.trace().encryption_parameters().cipher_modulus(),
            self.context.table(),
        )?;
        Ok(self.generate_circuit_bootstrap_key_with_main(secret, &transformed, parameters, rng))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        transformed: &NttNtruSecretKey<T>,
        parameters: CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let trace = NttNtruTraceKey::generate(
            secret,
            transformed,
            parameters.trace(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );
        let scheme_switch = NttNtruSchemeSwitchKey::generate(
            secret,
            transformed,
            parameters.output_basis(),
            parameters.scheme_switch(),
            self.context.table(),
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
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Pairs independently bound resources and a gadget key with configured CBS
    /// before compiling a default CBS/one-hot LUT or allocating projection storage.
    pub(crate) fn check_circuit_bootstrap_binding(
        &self,
        resources: &crate::bootstrap::BootstrapResources<'_, T, Table, LM>,
        circuit_key: &CircuitBootstrapKey<T>,
    ) -> Result<&crate::CbsParameters<T, LM>, crate::TfheEvaluationError> {
        let parameters = self
            .cbs_parameters()
            .ok_or(crate::TfheEvaluationError::MissingCircuitBootstrapParameters)?;
        if !core::ptr::eq(self, resources.context()) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if !circuit_key.is_compatible(parameters.gadget()) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }
        Ok(parameters)
    }
}
