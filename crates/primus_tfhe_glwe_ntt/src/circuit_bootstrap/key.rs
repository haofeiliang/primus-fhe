//! Evaluation keys for patched NTT circuit bootstrapping.

use primus_glwe::{NttGlweSchemeSwitchKey, NttGlweSecretKey, NttGlweTraceKey};
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;

use crate::{CircuitBootstrapParameters, ClientKey, KeyGenerationError, KeyGenerator};

/// Trace-projection and scheme-switching keys used after PBSManyLUT.
///
/// The ordinary PBS bootstrapping key remains in [`crate::ServerKey`]. This
/// object contains only the additional, optional circuit-bootstrapping
/// material. Both keys must use the same accumulator secret and the evaluator's
/// NTT representation; see [`crate::CircuitBootstrapEvaluator::try_from_parts`].
pub struct CircuitBootstrapKey<T: FheUint> {
    parameters: CircuitBootstrapParameters<T>,
    trace: NttGlweTraceKey<T>,
    scheme_switch: NttGlweSchemeSwitchKey<T>,
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
    #[inline]
    pub fn trace_key(&self) -> &NttGlweTraceKey<T> {
        &self.trace
    }

    /// Returns the GLev-to-GGSW scheme-switching key.
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
    /// Generates the optional trace-projection and scheme-switching keys.
    ///
    /// # Correctness
    ///
    /// For circuit bootstrapping, generate the ordinary server key from the same
    /// paired client secrets as `client_key` and use this context's NTT
    /// representation for generation and evaluation. The returned key uses
    /// `client_key`'s accumulator GLWE secret. Parameter/layout checks cannot
    /// establish that another server key uses that secret; see
    /// [`crate::CircuitBootstrapEvaluator::try_from_parts`].
    /// Imported accumulator coefficients must also satisfy
    /// [`NttGlweSecretKey::from_coeff_secret_key`]'s unsigned-magnitude bound.
    pub fn try_generate_circuit_bootstrap_key<R>(
        &mut self,
        client_key: &ClientKey<T>,
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
        client_key.check_compatible(tfhe)?;

        let coeff_secret_key = client_key.glwe_secret_key();
        let ntt_secret_key =
            NttGlweSecretKey::from_coeff_secret_key(coeff_secret_key, self.context.table());

        Ok(self.generate_circuit_bootstrap_key_with_main(
            client_key,
            &ntt_secret_key,
            parameters,
            rng,
        ))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        ntt_secret_key: &NttGlweSecretKey<T>,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let coeff_secret_key = client_key.glwe_secret_key();
        self.gadget.resize(parameters.trace().size());
        let trace = NttGlweTraceKey::generate(
            coeff_secret_key,
            ntt_secret_key,
            parameters.trace(),
            self.context.table(),
            rng,
            &mut self.gadget,
        );

        self.gadget.resize(parameters.scheme_switch().size());
        let scheme_switch = NttGlweSchemeSwitchKey::generate(
            coeff_secret_key,
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
