//! Evaluation keys for patched NTT circuit bootstrapping.

use primus_glwe::{GlweSecretKey, NttGlweSchemeSwitchKey, NttGlweSecretKey, NttGlweTraceKey};
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;

use crate::{CircuitBootstrapParameters, KeyGenerationError, KeyGenerator, TfheContext};

/// Trace-projection and scheme-switching keys used after PBSManyLUT.
///
/// The ordinary PBS bootstrapping key remains in [`crate::ServerKey`]. This
/// object contains only the additional, optional circuit-bootstrapping
/// material. Both keys must use the same accumulator secret and the evaluator's
/// NTT representation; see [`crate::CircuitBootstrapEvaluator::try_new`].
pub struct CircuitBootstrapKey<T: FheUint> {
    parameters: CircuitBootstrapParameters<T>,
    trace: NttGlweTraceKey<T>,
    scheme_switch: NttGlweSchemeSwitchKey<T>,
}

// A checked pair of CBS material and the chosen output parameters. The key
// binds output layout; a compatible alternate output basis remains valid.
pub(super) struct CircuitBootstrapBinding<'a, T: FheUint> {
    pub(super) key: &'a CircuitBootstrapKey<T>,
    pub(super) parameters: &'a CircuitBootstrapParameters<T>,
}

impl<'a, T: FheUint> CircuitBootstrapBinding<'a, T> {
    // Check caller-supplied parts before LUT/workspace preparation. Unlike NTRU,
    // GLWE can reuse scheme-switch material with another compatible output basis.
    pub(super) fn try_new(
        tfhe: &crate::TfheParameters<T>,
        parameters: &'a CircuitBootstrapParameters<T>,
        key: &'a CircuitBootstrapKey<T>,
    ) -> Result<Self, crate::TfheEvaluationError> {
        if !parameters.is_compatible(tfhe) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapParameters);
        }
        if !key.is_compatible(parameters) {
            return Err(crate::TfheEvaluationError::IncompatibleCircuitBootstrapKey);
        }
        Ok(Self { key, parameters })
    }
}

impl<T: FheUint> CircuitBootstrapKey<T> {
    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CircuitBootstrapParameters<T> {
        &self.parameters
    }

    pub(crate) fn is_compatible(&self, parameters: &CircuitBootstrapParameters<T>) -> bool {
        self.parameters.output_size() == parameters.output_size()
            && self.parameters.trace().size() == parameters.trace().size()
            && self.parameters.scheme_switch().size() == parameters.scheme_switch().size()
            && self.trace.basis() == parameters.trace().basis()
            && self.scheme_switch.key_basis() == parameters.scheme_switch().basis()
            && self.scheme_switch.output_size() == parameters.output_size()
            && self.scheme_switch.key_size() == parameters.scheme_switch().size()
    }

    /// Returns the trace key used for reverse-trace coefficient projection.
    #[must_use]
    #[inline]
    pub fn trace_key(&self) -> &NttGlweTraceKey<T> {
        &self.trace
    }

    /// Returns the GLev-to-GGSW scheme-switching key.
    #[must_use]
    #[inline]
    pub fn scheme_switch_key(&self) -> &NttGlweSchemeSwitchKey<T> {
        &self.scheme_switch
    }
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Generates trace-projection and scheme-switching keys from only the accumulator secret.
    ///
    /// # Correctness
    ///
    /// For circuit bootstrapping, generate the ordinary server key from the same
    /// accumulator secret as `accumulator_secret` and use this context's NTT
    /// representation for generation and evaluation. The returned key uses
    /// `accumulator_secret`. Parameter/layout checks cannot
    /// establish that another server key uses that secret; see
    /// [`crate::CircuitBootstrapEvaluator::try_new`].
    /// Imported accumulator coefficients must also satisfy
    /// [`NttGlweSecretKey::from_coeff_secret_key`]'s unsigned-magnitude bound.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        accumulator_secret: &GlweSecretKey<T>,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let tfhe = self.context.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(KeyGenerationError::IncompatibleCircuitBootstrapParameters);
        }
        tfhe.check_accumulator_secret_key(accumulator_secret)?;

        let ntt_secret_key =
            NttGlweSecretKey::from_coeff_secret_key(accumulator_secret, self.context.table());

        Ok(self.generate_circuit_bootstrap_key_with_main(
            accumulator_secret,
            &ntt_secret_key,
            parameters,
            rng,
        ))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        accumulator_secret: &GlweSecretKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        self.gadget.resize(parameters.trace().size());
        let trace = NttGlweTraceKey::generate(
            accumulator_secret,
            ntt_secret_key,
            parameters.trace(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );

        self.gadget.resize(parameters.scheme_switch().size());
        let scheme_switch = NttGlweSchemeSwitchKey::generate(
            accumulator_secret,
            ntt_secret_key,
            parameters.output_size(),
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

impl<T, Table> TfheContext<T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Generates the optional trace-projection and scheme-switching key material.
    ///
    /// # Correctness
    ///
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_key`]'s paired
    /// client-secret and NTT representation requirements. Compatibility checks
    /// do not establish that the ordinary server key uses the same secrets.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &self,
        accumulator_secret: &GlweSecretKey<T>,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_key(
            accumulator_secret,
            parameters,
            rng,
        )
    }
}
