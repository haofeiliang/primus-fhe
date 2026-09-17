use primus_encoding::ScaledCodec;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_reduce::RingContext;
use primus_tfhe::FactorizedLookupTable;
use primus_tfhe_glwe::{ClientKey, EncryptionKey};

use crate::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    CircuitBootstrapEvaluationError, CircuitBootstrapEvaluator, CircuitBootstrapKey,
    CircuitBootstrapKeyError, CircuitBootstrapParameters, Decryptor, Encryptor, Evaluator,
    FactorizedEvaluator, KeyGenerator, NttFactorizedLookupTable, ServerKey, TfheParameters,
    error::{
        LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    },
};

/// A validated binding between explicit-modulus TFHE parameters and an NTT
/// table.
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
    /// Binds TFHE parameters to a compatible NTT table.
    pub fn try_new(
        parameters: TfheParameters<T>,
        table: Table,
    ) -> Result<Self, TfheContextError<T>> {
        let expected = parameters.accumulator_glwe().poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }

        let expected = parameters.accumulator_glwe().cipher_modulus().value();
        let actual = table.modulus();
        if actual != expected {
            return Err(TfheContextError::ModulusMismatch { expected, actual });
        }

        Ok(Self { parameters, table })
    }

    /// Returns the validated TFHE parameters.
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the immutable NTT table.
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Generates a fresh compatible client/server key pair.
    pub fn generate_keys<R>(
        &self,
        rng: &mut R,
    ) -> Result<(ClientKey<T>, ServerKey<T>), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).generate(rng)
    }

    /// Creates a secret-key or public-key encryptor after checking compatibility.
    /// Public-key contracts follow [`EncryptionKey`].
    pub fn encryptor<'a, Key>(
        &'a self,
        key: &'a Key,
    ) -> Result<Encryptor<'a, T, Key>, TfheClientError>
    where
        Key: EncryptionKey<T, primus_modulus::BarrettModulus<T>, primus_modulus::BarrettModulus<T>>,
    {
        Encryptor::try_new(&self.parameters, key)
    }

    /// Creates a decryptor after checking the client key once.
    pub fn decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T>, TfheClientError> {
        Decryptor::try_new(&self.parameters, client_key)
    }

    /// Creates a programmable-bootstrap evaluator with reusable NTT workspace.
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
            != self.parameters.accumulator_glwe().cipher_modulus_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        let lookup_table = FactorizedLookupTable::try_new(
            input_domain_len,
            self.parameters.accumulator_glwe().poly_length(),
            output_count,
            self.parameters.input_plaintext_codec(),
            output_codec,
            function,
        )?;
        Ok(NttFactorizedLookupTable::new(self, lookup_table))
    }

    /// Creates a Boolean encryptor for a secret or public key, requiring `t = 4`.
    /// Public-key contracts follow [`EncryptionKey`].
    pub fn boolean_encryptor<'a, Key>(
        &'a self,
        key: &'a Key,
    ) -> Result<BooleanEncryptor<'a, T, Key>, BooleanError>
    where
        Key: EncryptionKey<T, primus_modulus::BarrettModulus<T>, primus_modulus::BarrettModulus<T>>,
    {
        BooleanEncryptor::try_new(&self.parameters, key)
    }

    /// Creates a Boolean decryptor after checking `t = 4` and the client key.
    pub fn boolean_decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<BooleanDecryptor<'a, T>, BooleanError> {
        BooleanDecryptor::try_new(&self.parameters, client_key)
    }

    /// Creates a Boolean evaluator with this context's PBS, gate LUTs and workspace.
    /// Requires `t = 4`; online `_to` operations reuse the allocated storage.
    pub fn boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BooleanEvaluator<'a, T, Table>, BooleanError> {
        BooleanEvaluator::try_new(&self.parameters, self.evaluator(server_key)?)
    }

    /// Generates the optional trace-projection and scheme-switching key material.
    ///
    /// # Correctness
    ///
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_key`]'s paired
    /// client-secret and NTT representation requirements. Compatibility checks
    /// do not establish that the ordinary server key uses the same secrets.
    pub fn generate_circuit_bootstrap_key<R>(
        &self,
        client_key: &ClientKey<T>,
        parameters: &CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<CircuitBootstrapKey<T>, CircuitBootstrapKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_key(client_key, parameters, rng)
    }

    /// Creates a patched NTT circuit-bootstrap evaluator with reusable workspace.
    /// Its [`CircuitBootstrapEvaluator::circuit_bootstrap_to`] calls allocate no
    /// heap memory after construction.
    ///
    /// # Correctness
    ///
    /// Inherits [`CircuitBootstrapEvaluator::try_new`]'s requirement that the
    /// server and circuit keys use the same paired client secrets and this
    /// context's NTT representation. Parameter/layout/basis checks do not verify
    /// secret or transform identity.
    pub fn circuit_bootstrap_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
        parameters: &'a CircuitBootstrapParameters<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
    ) -> Result<CircuitBootstrapEvaluator<'a, T, Table>, CircuitBootstrapEvaluationError> {
        CircuitBootstrapEvaluator::try_new(self, server_key, parameters, circuit_key)
    }

    /// Decomposes this context into its parameters and NTT table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
