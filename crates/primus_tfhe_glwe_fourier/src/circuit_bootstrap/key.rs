use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{FourierGlweSchemeSwitchKey, FourierGlweSecretKey, FourierGlweTraceKey};

use crate::{CircuitBootstrapParameters, ClientKey, KeyGenerationError, KeyGenerator};

/// Optional trace-projection and GLev-to-Fourier-GGSW scheme-switch keys.
///
/// Both keys use the client's accumulator GLWE secret and the generating
/// context's FFT table. The ordinary PBS keys remain in [`crate::ServerKey`].
/// Layout and basis equality do not establish secret or FFT representation
/// identity; consumers must use the same secret and FFT table instance as
/// generation; see [`crate::CircuitBootstrapEvaluator::try_from_parts`].
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    parameters: CircuitBootstrapParameters<T>,
    trace: FourierGlweTraceKey<T>,
    scheme_switch: FourierGlweSchemeSwitchKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapKey<T> {
    /// Returns the CBS parameters selected when this material was generated.
    #[must_use]
    pub fn parameters(&self) -> &CircuitBootstrapParameters<T> {
        &self.parameters
    }

    pub(crate) fn is_compatible(&self, parameters: &CircuitBootstrapParameters<T>) -> bool {
        // Generation binds both keys to the same GLWE layout. The scheme-switch
        // key exposes that layout; the trace key only needs a basis comparison.
        self.scheme_switch.output_size() == parameters.output_size()
            && self.scheme_switch.key_size() == parameters.scheme_switch().size()
            && self.scheme_switch.key_basis() == parameters.scheme_switch().basis()
            && self.trace.basis() == parameters.trace().basis()
    }

    /// Returns the key for reverse-trace coefficient projection.
    #[must_use]
    #[inline]
    pub fn trace_key(&self) -> &FourierGlweTraceKey<T> {
        &self.trace
    }

    /// Returns the GLev-to-Fourier-GGSW scheme-switch key.
    #[must_use]
    #[inline]
    pub fn scheme_switch_key(&self) -> &FourierGlweSchemeSwitchKey<T> {
        &self.scheme_switch
    }
}

impl<'a, T, Table> KeyGenerator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates optional CBS keys, reusing this generator's Fourier workspace.
    ///
    /// Rejects incompatible circuit parameters or client keys before sampling.
    ///
    /// # Correctness
    ///
    /// Both keys encrypt under `client_key`'s accumulator GLWE secret. Generate
    /// the ordinary PBS server key from the same client key and use this
    /// context's FFT table for evaluation. Compatibility checks cannot identify
    /// the actual secret or distinguish FFT representations with equal lengths.
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

        let secret = client_key.glwe_secret_key();
        let fourier_secret = FourierGlweSecretKey::from_coeff_secret_key(secret, &mut self.fft);

        Ok(self.generate_circuit_bootstrap_key_with_main(
            client_key,
            &fourier_secret,
            parameters,
            rng,
        ))
    }

    /// Uses the accumulator transform already prepared for ordinary PBS key generation.
    pub(crate) fn generate_circuit_bootstrap_key_with_main<R>(
        &mut self,
        client_key: &ClientKey<T>,
        fourier_secret: &FourierGlweSecretKey,
        parameters: CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> CircuitBootstrapKey<T>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let secret = client_key.glwe_secret_key();
        self.gadget.resize(parameters.trace().size());
        let trace = FourierGlweTraceKey::generate(
            secret,
            fourier_secret,
            parameters.trace(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );

        self.gadget.resize(parameters.scheme_switch().size());
        let scheme_switch = FourierGlweSchemeSwitchKey::generate(
            secret,
            fourier_secret,
            parameters.output_size(),
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
