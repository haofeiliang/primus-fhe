use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{FourierGlweSchemeSwitchKey, FourierGlweSecretKey, FourierGlweTraceKey};

use crate::{CircuitBootstrapParameters, ClientKey, KeyGenerator, TfheKeyError};

/// An error produced while generating a circuit-bootstrapping key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CircuitBootstrapKeyError {
    /// The circuit parameters use another accumulator layout or input plaintext modulus.
    #[error("circuit-bootstrap parameters are incompatible with the TFHE context")]
    IncompatibleParameters,
    /// The client key does not match the TFHE context.
    #[error(transparent)]
    ClientKey(#[from] TfheKeyError),
}

/// Optional trace-projection and GLev-to-Fourier-GGSW scheme-switch keys.
///
/// Both keys use the client's accumulator GLWE secret and the generating
/// context's FFT table. The ordinary PBS keys remain in [`crate::ServerKey`].
/// Layout and basis equality do not establish secret or FFT representation
/// identity; consumers must use the same secret and FFT table instance as
/// generation. The complete Fourier CBS evaluator is not yet provided.
pub struct CircuitBootstrapKey<T: TorusFftValue> {
    trace: FourierGlweTraceKey<T>,
    scheme_switch: FourierGlweSchemeSwitchKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapKey<T> {
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
        parameters: &CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, CircuitBootstrapKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let tfhe = self.context.parameters();
        if !parameters.is_compatible(tfhe) {
            return Err(CircuitBootstrapKeyError::IncompatibleParameters);
        }
        client_key.check_compatible(tfhe)?;

        let secret = client_key.glwe_secret_key();
        let fourier_secret = FourierGlweSecretKey::from_coeff_secret_key(secret, &mut self.fft);

        self.gadget.resize(parameters.trace().size());
        let trace = FourierGlweTraceKey::generate(
            secret,
            &fourier_secret,
            parameters.trace(),
            &mut self.fft,
            rng,
            &mut self.gadget,
        );

        self.gadget.resize(parameters.scheme_switch().size());
        let scheme_switch = FourierGlweSchemeSwitchKey::generate(
            secret,
            &fourier_secret,
            parameters.output_size(),
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
