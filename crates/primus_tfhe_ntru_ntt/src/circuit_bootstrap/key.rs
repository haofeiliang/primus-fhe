//! Optional trace and scheme-switch material under the accumulator secret.

use primus_integer::FheUint;
use primus_ntru::{NttNtruSchemeSwitchKey, NttNtruSecretKey, NttNtruTraceKey};
use primus_ntt::MonomialNttTable;

use crate::{CircuitBootstrapParameters, KeyGenerationError, KeyGenerator, TfheContext};

/// Additional keys for NTRU CBS; ordinary BR material is owned by [`crate::BlindRotationKey`].
/// Both keys use the accumulator secret, not the post-PBS client secret.
/// Publishing the scheme-switch material requires the secret-dependent-message
/// security assumption documented on [`NttNtruSchemeSwitchKey`].
pub struct CircuitBootstrapKey<T: FheUint> {
    parameters: CircuitBootstrapParameters<T>,
    trace: NttNtruTraceKey<T>,
    scheme_switch: NttNtruSchemeSwitchKey<T>,
}

// Classic BR material paired with available CBS keys and their complete output
// basis. NTRU scheme switching cannot substitute a different output basis.
pub(super) struct CircuitBootstrapBinding<'a, T: FheUint> {
    pub(super) classic_controls: crate::ClassicControls<'a, T>,
    pub(super) key: &'a CircuitBootstrapKey<T>,
    pub(super) parameters: &'a CircuitBootstrapParameters<T>,
}

impl<'a, T: FheUint> CircuitBootstrapBinding<'a, T> {
    // Reject sparse controls and incompatible CBS parameters before online use.
    // Receiving material and checking its geometry do not prove actual key identity.
    pub(super) fn try_new<LM: primus_reduce::RingContext<T>>(
        tfhe: &crate::TfheParameters<T, LM>,
        controls: Option<crate::ClassicControls<'a, T>>,
        key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, crate::TfheEvaluationError> {
        let classic_controls =
            controls.ok_or(crate::TfheEvaluationError::UnsupportedSparseBootstrapping)?;
        let parameters = key.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        Ok(Self {
            classic_controls,
            key,
            parameters,
        })
    }
}

impl<T: FheUint> CircuitBootstrapKey<T> {
    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CircuitBootstrapParameters<T> {
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
    /// selects the independent noise/decomposition/security budgets described on
    /// [`CircuitBootstrapParameters`]. Actual secret identity must be shared with
    /// the server key later used by the evaluator.
    /// Accumulator coefficients inherit
    /// [`NttNtruSecretKey::try_from_coeff_secret_key`]'s magnitude bound.
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
        let transformed = NttNtruSecretKey::try_from_coeff_secret_key(
            secret,
            parameters.trace().inner().cipher_modulus(),
            self.context.table(),
        )?;
        Ok(self.generate_circuit_bootstrap_key_with_main(secret, &transformed, parameters, rng))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        secret: &primus_ntru::NtruSecretKey<T>,
        transformed: &NttNtruSecretKey<T>,
        parameters: CircuitBootstrapParameters<T>,
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
