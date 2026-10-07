//! Material generation for ring-output CBS workflows.

use primus_fft::{FftTable, TorusFftValue};

use crate::{
    BlindRotationConfig, BlindRotationKey, BootstrapResources, CircuitBootstrapConfig,
    CircuitBootstrapKey, CircuitBootstrapParameters, ClientKey, KeyGenerationError, KeyGenerator,
    TfheContext, TfheEvaluationError,
};

/// Evaluation material for ring-output circuit bootstrapping.
/// NTRU CBS and one-hot produce ring outputs, so this bundle contains no LWE return key.
/// The CBS key is always present. For PBS/MVB or high-precision lookup requiring
/// an ordinary return path, use [`crate::ServerKey`] instead.
pub struct CircuitBootstrapServerKey<T: TorusFftValue> {
    blind_rotation: BlindRotationKey<T>,
    circuit_bootstrap: CircuitBootstrapKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapServerKey<T> {
    /// Moves existing components into a bundle without copying or checking them.
    /// Resource/evaluator binding validates layouts; shared secret and transform
    /// identity remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation: BlindRotationKey<T>,
        circuit_bootstrap: CircuitBootstrapKey<T>,
    ) -> Self {
        Self {
            blind_rotation,
            circuit_bootstrap,
        }
    }

    /// Borrows the classic or sparse BR material.
    #[must_use]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation
    }

    /// Borrows the required trace and scheme-switch material.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> &CircuitBootstrapKey<T> {
        &self.circuit_bootstrap
    }

    /// Moves components out for reuse, for example when adding an ordinary return path.
    #[must_use]
    pub fn into_parts(self) -> (BlindRotationKey<T>, CircuitBootstrapKey<T>) {
        (self.blind_rotation, self.circuit_bootstrap)
    }

    /// Binds BR and required input preparation, with no output-return workspace.
    /// Bind the CBS evaluator separately with [`Self::circuit_bootstrap_key`].
    /// Inherits [`BootstrapResources::try_new`]'s secret/transform requirements.
    pub fn bootstrap_resources<'a, Table, LM>(
        &'a self,
        context: &'a TfheContext<T, Table, LM>,
    ) -> Result<BootstrapResources<'a, T, Table, LM>, TfheEvaluationError>
    where
        Table: FftTable,
        LM: primus_reduce::RingContext<T>,
    {
        context.bootstrap_resources(&self.blind_rotation)
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates a fresh client and the material needed for ring-output CBS.
    /// NTRU CBS and one-hot produce ring outputs, so this bundle contains no LWE return key.
    /// The accepted accumulator transform and inverse are shared by BR and CBS,
    /// then dropped before returning the pair. Matching retries only the public sparse map.
    ///
    /// # Errors
    /// CBS and sparse configuration errors precede secret sampling. Propagates
    /// secret-generation and matching errors without returning partial material.
    ///
    /// # Correctness
    /// Requires the BR/CBS and accumulator-conversion conditions documented by
    /// [`Self::try_generate`], but not the return-q magnitude bound. No LWE return
    /// key is generated, and the accepted ring secret is not checked against q.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        blind_rotation: BlindRotationConfig,
        circuit_bootstrap: CircuitBootstrapConfig,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        let parameters = CircuitBootstrapParameters::try_from_config(
            self.context.parameters(),
            circuit_bootstrap,
        )?;
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let (client, transformed) = self.generate_client_key_with_main(rng)?;
        let blind_rotation =
            self.generate_blind_rotation_key_with_main(&client, &transformed, sparse_layout, rng)?;
        let circuit_bootstrap = self.generate_circuit_bootstrap_key_with_main(
            client.accumulator_ntru_secret_key(),
            &transformed,
            parameters,
            rng,
        );
        drop(transformed);
        Ok((
            client,
            CircuitBootstrapServerKey::new(blind_rotation, circuit_bootstrap),
        ))
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates a client and a ring-output CBS bundle with only the required keys.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_keys`]'s contracts.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        blind_rotation: BlindRotationConfig,
        circuit_bootstrap: CircuitBootstrapConfig,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_keys(
            blind_rotation,
            circuit_bootstrap,
            rng,
        )
    }
}
