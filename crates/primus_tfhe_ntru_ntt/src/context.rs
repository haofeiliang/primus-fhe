use primus_encoding::ScaledCodec;
use primus_integer::FheUint;
use primus_ntru::NtruCiphertext;
use primus_ntt::MonomialNttTable;
use primus_reduce::RingContext;
use primus_tfhe_ntru::{ClientError, LwePublicKey};

use crate::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator, CircuitBootstrapConfig,
    ClientKey, Decryptor, Encryptor, Evaluator, FactorizedEvaluator, FactorizedLookupTable,
    KeyGenerationError, KeyGenerator, LookupTableError, LweCiphertext, NttFactorizedLookupTable,
    ServerKey, TfheClientError, TfheContextError, TfheEvaluationError, TfheParameters,
};

/// Validated binding between NTRU TFHE parameters and one exact NTT table.
pub struct TfheContext<T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    parameters: TfheParameters<T>,
    table: Table,
}

impl<T, Table> TfheContext<T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Builds the selected NTT table using the accumulator length and modulus.
    ///
    /// Preserves table-construction errors, including an unavailable primitive
    /// root or unsupported modulus. Use [`Self::try_new`] to inject an existing table.
    pub fn try_from_parameters(parameters: TfheParameters<T>) -> Result<Self, TfheContextError<T>> {
        let accumulator = parameters.accumulator_ntru();
        let table = Table::new(
            accumulator.poly_length().trailing_zeros(),
            accumulator.cipher_modulus(),
        )?;
        Ok(Self { parameters, table })
    }

    /// Binds parameters to a compatible NTT table.
    pub fn try_new(
        parameters: TfheParameters<T>,
        table: Table,
    ) -> Result<Self, TfheContextError<T>> {
        let expected = parameters.poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        let expected = parameters.accumulator_ntru().cipher_modulus().value();
        let actual = table.modulus();
        if actual != expected {
            return Err(TfheContextError::ModulusMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated mathematical parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the bound NTT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Allocates zero storage for an external LWE ciphertext (mask and body).
    /// Uses the dimension selected by the parameters; no key or encryption is involved.
    #[must_use]
    pub fn allocate_lwe_ciphertext(&self) -> LweCiphertext<T> {
        LweCiphertext::zero(self.parameters.external_lwe_dimension())
    }

    /// Allocates a zeroed coefficient-domain NTRU with the accumulator layout.
    /// Requires only public parameters; this does not encrypt a message.
    #[must_use]
    pub fn allocate_accumulator_ciphertext(&self) -> NtruCiphertext<Vec<T>> {
        NtruCiphertext::zero(self.parameters.accumulator_ntru().poly_length())
    }

    /// Prepares private-key encryption/decryption in the accumulator ring domain.
    /// Inherits [`crate::AccumulatorClient::try_new`]'s contracts and errors.
    pub fn accumulator_client(
        &self,
        client_key: &ClientKey<T>,
    ) -> Result<crate::AccumulatorClient<'_, T, Table>, TfheClientError> {
        crate::AccumulatorClient::try_new(self, client_key)
    }

    /// Generates a fresh client/server pair; `None` selects PBS only and
    /// `Some(config)` also generates the configured CBS material.
    /// Inherits [`KeyGenerator::try_generate`]'s rejection-sampling errors and CBS requirements.
    pub fn try_generate_keys<R>(
        &self,
        circuit_bootstrap: Option<CircuitBootstrapConfig>,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), KeyGenerationError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate(circuit_bootstrap, rng)
    }

    /// Generates experimental sparse PBS material for a fixed-weight binary client.
    /// Inherits [`KeyGenerator::try_generate_sparse_server_key`]'s sampling, errors
    /// and noise contracts. Reuses the ordinary evaluator; CBS/MVB are unsupported.
    pub fn try_generate_sparse_server_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        copy_count: usize,
        bucket_count: usize,
        rng: &mut R,
    ) -> Result<ServerKey<T>, KeyGenerationError> {
        KeyGenerator::new(self).try_generate_sparse_server_key(
            client_key,
            copy_count,
            bucket_count,
            rng,
        )
    }

    /// Creates an encryptor after checking the family client key.
    pub fn encryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Encryptor<'a, T>, TfheClientError> {
        self.parameters.encryptor(client_key)
    }

    /// Checks an external LWE public key and creates its encryptor.
    /// Key identity and noise requirements follow [`primus_tfhe::EncryptionKey`].
    pub fn public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<Encryptor<'a, T, &'a LwePublicKey<T>>, ClientError> {
        self.parameters.public_encryptor(public_key)
    }

    /// Creates a decryptor after checking the family client key.
    pub fn decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T>, TfheClientError> {
        self.parameters.decryptor(client_key)
    }

    /// Creates an evaluator with reusable NTT and coefficient workspaces.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }

    /// Creates reusable MVB workspace. See [`FactorizedEvaluator::try_new`] for
    /// the server-key secret and NTT representation requirements.
    pub fn factorized_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<FactorizedEvaluator<'a, T, Table>, TfheEvaluationError> {
        FactorizedEvaluator::try_new(self, server_key)
    }

    /// Compiles and NTT-prepares a fixed-scale MVB program for this context.
    ///
    /// `input_domain_len` selects a nonempty prefix of the parameter codec's
    /// front half; `output_count` is positive and unpadded. Outputs must lie in
    /// the supplied Scaled codec's domain, and its ciphertext modulus must match
    /// the accumulator. Callback order and noise requirements follow
    /// [`FactorizedLookupTable::try_new`]. The result borrows this context and
    /// may only be evaluated by its [`FactorizedEvaluator`].
    pub fn compile_factorized_lookup_table_fn<OM, F>(
        &self,
        output_codec: &ScaledCodec<T, OM>,
        input_domain_len: usize,
        output_count: usize,
        function: F,
    ) -> Result<NttFactorizedLookupTable<'_, T, Table>, LookupTableError>
    where
        OM: RingContext<T>,
        F: Fn(usize, usize) -> T,
    {
        if output_codec.ciphertext_modulus().explicit_value()
            != self.parameters.accumulator_ntru().cipher_modulus_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        let lookup_table = FactorizedLookupTable::try_new(
            input_domain_len,
            self.parameters.poly_length(),
            output_count,
            self.parameters.input_plaintext_codec(),
            output_codec,
            function,
        )?;
        Ok(NttFactorizedLookupTable::new(self, lookup_table))
    }

    /// Creates a secret-key Boolean encryptor, requiring `t = 4`.
    pub fn boolean_encryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<BooleanEncryptor<'a, T>, TfheClientError> {
        Ok(BooleanEncryptor::try_new(self.encryptor(client_key)?)?)
    }

    /// Creates a public-key Boolean encryptor, requiring `t = 4`.
    /// Inherits [`Self::public_encryptor`]'s key identity and noise requirements.
    pub fn boolean_public_encryptor<'a>(
        &'a self,
        public_key: &'a LwePublicKey<T>,
    ) -> Result<BooleanEncryptor<'a, T, &'a LwePublicKey<T>>, BooleanError> {
        BooleanEncryptor::try_new(self.public_encryptor(public_key)?)
    }

    /// Creates a Boolean decryptor after checking the client key and `t = 4`.
    pub fn boolean_decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<BooleanDecryptor<'a, T>, TfheClientError> {
        Ok(BooleanDecryptor::try_new(self.decryptor(client_key)?)?)
    }

    /// Creates a Boolean evaluator with this context's PBS, gate LUTs and workspace.
    /// Requires `t = 4`; online `_to` operations reuse the allocated storage.
    pub fn boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BooleanEvaluator<'a, T, Table>, TfheEvaluationError> {
        BooleanEvaluator::try_new(
            self.parameters.external_lwe_dimension(),
            self.parameters.accumulator_ntru().poly_length(),
            self.parameters.input_plaintext_codec(),
            self.parameters.accumulator_ntru().cipher_modulus(),
            self.evaluator(server_key)?,
        )
    }

    /// Generates optional CBS material under this client's accumulator secret.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_key`]'s contracts.
    pub fn try_generate_circuit_bootstrap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        parameters: crate::CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<crate::CircuitBootstrapKey<T>, crate::KeyGenerationError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_key(client_key, parameters, rng)
    }

    /// Binds the server key's optional CBS material to reusable workspace.
    /// Returns an error if the capability is absent or incompatible.
    ///
    /// # Correctness
    /// Inherits [`crate::CircuitBootstrapEvaluator::try_new`]'s transform requirements.
    pub fn circuit_bootstrap_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<crate::CircuitBootstrapEvaluator<'a, T, Table>, crate::TfheEvaluationError> {
        crate::CircuitBootstrapEvaluator::try_new(self, server_key)
    }

    /// Decomposes this context into parameters and its NTT table.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
