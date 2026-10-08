//! Material generation for ring-output CBS workflows.

use primus_fft::{FftTable, TorusFftValue};
use primus_glwe::{FourierGlweKeySwitchingKey, FourierGlweSecretKey};

use crate::{
    BlindRotationAlgorithm, BlindRotationKey, BootstrapResources, CbsGadgetConfig, CbsParameters,
    CircuitBootstrapKey, ClientKey, KeyGenerationError, KeyGenerator, TfheContext,
    TfheEvaluationError,
};

/// Evaluation material for ring-output circuit bootstrapping.
/// GLWE KS→BR includes input KS; BR→KS contains only BR and CBS material.
/// The CBS key is always present. For ordinary PBS/MVB, use [`crate::ServerKey`] instead.
pub struct CircuitBootstrapServerKey<T: TorusFftValue> {
    blind_rotation: BlindRotationKey<T>,
    input_key_switching: Option<FourierGlweKeySwitchingKey<T>>,
    circuit_bootstrap: CircuitBootstrapKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapServerKey<T> {
    /// Moves existing components into a bundle without copying or checking them.
    /// Pass input KS for KS→BR and `None` for BR→KS. Resource/evaluator binding
    /// validates layouts; shared secret and transform identity remain caller requirements.
    #[must_use]
    pub fn new(
        blind_rotation: BlindRotationKey<T>,
        input_key_switching: Option<FourierGlweKeySwitchingKey<T>>,
        circuit_bootstrap: CircuitBootstrapKey<T>,
    ) -> Self {
        Self {
            blind_rotation,
            input_key_switching,
            circuit_bootstrap,
        }
    }

    /// Borrows the classic or sparse BR material.
    #[must_use]
    pub fn blind_rotation_key(&self) -> &BlindRotationKey<T> {
        &self.blind_rotation
    }

    /// Borrows the input KS material; generated bundles contain it only for KS→BR.
    #[must_use]
    pub fn input_key_switching_key(&self) -> Option<&FourierGlweKeySwitchingKey<T>> {
        self.input_key_switching.as_ref()
    }

    /// Borrows the required trace and scheme-switch material.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> &CircuitBootstrapKey<T> {
        &self.circuit_bootstrap
    }

    /// Moves components out for reuse, for example when adding an ordinary return path.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BlindRotationKey<T>,
        Option<FourierGlweKeySwitchingKey<T>>,
        CircuitBootstrapKey<T>,
    ) {
        (
            self.blind_rotation,
            self.input_key_switching,
            self.circuit_bootstrap,
        )
    }

    /// Binds BR and required input preparation, with no output-return workspace.
    /// Bind the CBS evaluator separately with [`Self::circuit_bootstrap_key`].
    /// Inherits [`BootstrapResources::try_new`]'s secret/transform requirements.
    pub fn bootstrap_resources<'a, Table>(
        &'a self,
        context: &'a TfheContext<T, Table>,
    ) -> Result<BootstrapResources<'a, T, Table>, TfheEvaluationError>
    where
        Table: FftTable,
    {
        context.bootstrap_resources(&self.blind_rotation, self.input_key_switching.as_ref())
    }
}

impl<T, Table> KeyGenerator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates a fresh client and the material needed for ring-output CBS.
    /// GLWE KS→BR includes input KS; BR→KS contains only BR and CBS material.
    /// The accepted accumulator transform is shared by BR and CBS, then dropped
    /// before preparing any input KS. Matching retries only the public sparse map.
    ///
    /// # Errors
    /// CBS and sparse configuration errors precede secret sampling. Propagates
    /// secret-generation and matching errors without returning partial material.
    ///
    /// # Correctness
    /// Requires the BR/CBS noise budgets documented by
    /// [`Self::try_generate`] for the selected algorithm; no output KS is generated.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        blind_rotation: BlindRotationAlgorithm,
        circuit_bootstrap: CbsGadgetConfig,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        let parameters =
            CbsParameters::try_from_config(self.context.parameters(), circuit_bootstrap)?;
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let client = ClientKey::generate(self.context.parameters(), rng);
        let transformed =
            FourierGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), &mut self.fft);
        let blind_rotation =
            self.generate_blind_rotation_key_with_main(&client, &transformed, sparse_layout, rng)?;
        let circuit_bootstrap = self.generate_circuit_bootstrap_key_with_main(
            client.glwe_secret_key(),
            &transformed,
            parameters,
            rng,
        );
        drop(transformed);
        let input_key_switching = match self.context.parameters().pbs_order() {
            crate::PbsOrder::BootstrapKeyswitch => None,
            crate::PbsOrder::KeyswitchBootstrap => {
                Some(self.generate_glwe_key_switching_key(&client, rng))
            }
        };
        Ok((
            client,
            CircuitBootstrapServerKey::new(blind_rotation, input_key_switching, circuit_bootstrap),
        ))
    }
}

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Generates a client and a ring-output CBS bundle with only the required keys.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_keys`]'s contracts.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        blind_rotation: BlindRotationAlgorithm,
        circuit_bootstrap: CbsGadgetConfig,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_keys(
            blind_rotation,
            circuit_bootstrap,
            rng,
        )
    }
}
