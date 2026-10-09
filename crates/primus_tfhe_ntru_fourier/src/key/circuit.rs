//! CBS material composed with the ordinary BR and KS server key.

use primus_fft::{FftTable, TorusFftValue};
use primus_ntru::FourierNtruSecretKey;

use crate::{
    BootstrapResources, CbsGadgetParameters, CircuitBootstrapKey, ClientKey, KeyGenerationError,
    KeyGenerator, ServerKey, TfheContext, TfheEvaluationError,
};

/// Complete CBS material with one BR key, one KS key and trace/scheme-switch keys.
/// The ordinary server key also serves PBS and downstream LWE returns; CBS
/// resources allocate only the input/BR scratch used by circuit bootstrapping.
pub struct CircuitBootstrapServerKey<T: TorusFftValue> {
    server_key: ServerKey<T>,
    circuit_bootstrap: CircuitBootstrapKey<T>,
}

impl<T: TorusFftValue> CircuitBootstrapServerKey<T> {
    /// Moves existing material into a bundle without copying or checking it.
    /// Binding validates layouts; actual paired secrets and transform identity
    /// remain caller requirements.
    #[must_use]
    pub fn new(server_key: ServerKey<T>, circuit_bootstrap: CircuitBootstrapKey<T>) -> Self {
        Self {
            server_key,
            circuit_bootstrap,
        }
    }

    /// Borrows the BR and KS material for PBS or downstream LWE returns.
    #[must_use]
    pub fn server_key(&self) -> &ServerKey<T> {
        &self.server_key
    }

    /// Borrows the required trace and scheme-switch material.
    #[must_use]
    pub fn circuit_bootstrap_key(&self) -> &CircuitBootstrapKey<T> {
        &self.circuit_bootstrap
    }

    /// Moves out ordinary and CBS material without copying ciphertext buffers.
    #[must_use]
    pub fn into_parts(self) -> (ServerKey<T>, CircuitBootstrapKey<T>) {
        (self.server_key, self.circuit_bootstrap)
    }

    /// Binds CBS input preparation and BR without allocating output-return scratch.
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
        context.bootstrap_resources(self.server_key.blind_rotation_key())
    }
}

impl<T, Table, LM> KeyGenerator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates a client and complete CBS material, including the ordinary KS key.
    /// Shares the accepted ring representation between BR and CBS, then releases
    /// it before preparing KS. Sparse matching retries only the public map.
    ///
    /// # Errors
    /// Missing CBS state and invalid sparse choices precede secret sampling.
    /// Propagates secret-generation, return-domain and matching failures.
    ///
    /// # Correctness
    /// Inherits [`Self::try_generate`]'s BR/KS contracts and
    /// [`Self::try_generate_circuit_bootstrap_key`]'s CBS noise requirements.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        self.generate_circuit_pair(
            operation.pbs_parameters().key_switching(),
            operation.as_ref().algorithm(),
            operation.gadget(),
            rng,
        )
    }

    /// Generates a CBS pair from independently prepared KS/CBS parameters.
    /// Checks their common domain before sampling any secrets or key rows.
    /// Inherits [`Self::try_generate_circuit_bootstrap_keys`]'s numerical contracts.
    pub fn try_generate_circuit_bootstrap_keys_with_parameters<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        blind_rotation: crate::BlindRotationMethod,
        circuit: &CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        self.context
            .parameters()
            .check_lwe_return_parameters(key_switching)?;
        self.check_circuit_bootstrap_parameters(circuit)?;
        self.generate_circuit_pair(key_switching, blind_rotation, circuit, rng)
    }

    /// Samples secrets only after the owning boundary paired KS/CBS parameters.
    fn generate_circuit_pair<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        blind_rotation: crate::BlindRotationMethod,
        circuit: &CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let (client, transformed) = self.generate_client_key_with_main(rng)?;
        let server = self.generate_circuit_server_with_main(
            key_switching,
            &client,
            transformed,
            sparse_layout,
            circuit,
            rng,
        )?;
        Ok((client, server))
    }

    /// Generates the configured CBS bundle for independently supplied client secrets.
    /// Checks compatibility before converting the secret or sampling key rows.
    /// Inherits [`Self::try_generate_circuit_bootstrap_keys`]'s numerical contracts.
    pub fn try_generate_circuit_bootstrap_server_key<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        client: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        let operation = self
            .context
            .cbs_parameters()
            .ok_or(KeyGenerationError::MissingCircuitBootstrapParameters)?;
        self.generate_circuit_for_client(
            operation.pbs_parameters().key_switching(),
            client,
            operation.as_ref().algorithm(),
            operation.gadget(),
            rng,
        )
    }

    /// Generates CBS material with independently prepared KS/CBS parameters.
    /// Checks their common domain before secret conversion or key-row sampling.
    /// Inherits [`Self::try_generate_circuit_bootstrap_keys`]'s numerical contracts;
    /// the supplied decomposition/noise choices need their own joint noise budget.
    pub fn try_generate_circuit_bootstrap_server_key_with_parameters<
        R: rand::Rng + rand::CryptoRng,
    >(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        client: &ClientKey<T>,
        blind_rotation: crate::BlindRotationMethod,
        circuit: &CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        self.context
            .parameters()
            .check_lwe_return_parameters(key_switching)?;
        self.check_circuit_bootstrap_parameters(circuit)?;
        self.generate_circuit_for_client(key_switching, client, blind_rotation, circuit, rng)
    }

    /// Validates imported secrets, then shares their ring representation across BR/CBS.
    fn generate_circuit_for_client<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        client: &ClientKey<T>,
        blind_rotation: crate::BlindRotationMethod,
        circuit: &CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        client.check_compatible(self.context.parameters())?;
        let sparse_layout = self.prepare_blind_rotation(blind_rotation)?;
        let transformed = FourierNtruSecretKey::try_from_coeff_secret_key(
            client.accumulator_ntru_secret_key(),
            &mut self.fft,
        )?;
        self.generate_circuit_server_with_main(
            key_switching,
            client,
            transformed,
            sparse_layout,
            circuit,
            rng,
        )
    }

    /// Consumes the validated ring representation for BR/CBS before allocating KS rows.
    fn generate_circuit_server_with_main<R: rand::Rng + rand::CryptoRng>(
        &mut self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        client: &ClientKey<T>,
        transformed: FourierNtruSecretKey,
        sparse_layout: Option<crate::sparse::SparseKeyLayout>,
        circuit: &CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        let blind_rotation =
            self.generate_blind_rotation_key_with_main(client, &transformed, sparse_layout, rng)?;
        let circuit_bootstrap = self.generate_circuit_bootstrap_key_with_main(
            client.accumulator_ntru_secret_key(),
            &transformed,
            circuit.clone(),
            rng,
        );
        drop(transformed);
        let key = primus_ntru::NtruLweKeySwitchingKey::generate(
            client.accumulator_ntru_secret_key(),
            self.context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus(),
            client.external_lwe_secret_key(),
            key_switching.lwe(),
            key_switching.basis().clone(),
            rng,
        );
        Ok(CircuitBootstrapServerKey::new(
            ServerKey::new(blind_rotation, key),
            circuit_bootstrap,
        ))
    }

    /// Checks independently prepared CBS state before any secret or key sampling.
    fn check_circuit_bootstrap_parameters(
        &self,
        circuit_bootstrap: &CbsGadgetParameters<T>,
    ) -> Result<(), KeyGenerationError> {
        if !circuit_bootstrap.is_compatible(self.context.parameters()) {
            return Err(KeyGenerationError::IncompatibleCircuitBootstrapParameters);
        }
        Ok(())
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Generates paired client/CBS keys with one BR and one KS key.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_keys`]'s contracts.
    pub fn try_generate_circuit_bootstrap_keys<R: rand::Rng + rand::CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_keys(rng)
    }

    /// Generates a complete CBS bundle for an existing client.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_server_key`]'s contracts.
    pub fn try_generate_circuit_bootstrap_server_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client: &ClientKey<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapServerKey<T>, KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_server_key(client, rng)
    }

    /// Generates a CBS pair using independently prepared material parameters.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_keys_with_parameters`]'s contracts.
    pub fn try_generate_circuit_bootstrap_keys_with_parameters<R: rand::Rng + rand::CryptoRng>(
        &self,
        key_switching: &crate::LweReturnParameters<T, LM>,
        blind_rotation: crate::BlindRotationMethod,
        circuit: &CbsGadgetParameters<T>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, CircuitBootstrapServerKey<T>), KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_keys_with_parameters(
            key_switching,
            blind_rotation,
            circuit,
            rng,
        )
    }
}
