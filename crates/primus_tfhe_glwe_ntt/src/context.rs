use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_tfhe::{InterleavedLookupTable, LookupTable};
use primus_tfhe_glwe::GlweClientKey as ClientKey;

use crate::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    CircuitBootstrapEvaluationError, CircuitBootstrapEvaluator, CircuitBootstrapKey,
    CircuitBootstrapKeyError, CircuitBootstrapParameters, Decryptor, Encryptor, Evaluator,
    KeyGenerator, ServerKey, TfheParameters,
    error::{
        LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    },
};

/// A validated binding between explicit-modulus TFHE parameters and an NTT
/// table.
pub struct TfheContext<T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    parameters: TfheParameters<T>,
    table: Table,
}

impl<T, Table> TfheContext<T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    /// Binds TFHE parameters to a compatible NTT table.
    pub fn try_new(
        parameters: TfheParameters<T>,
        table: Table,
    ) -> Result<Self, TfheContextError<T>> {
        let expected = parameters.glwe().poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }

        let expected = parameters.glwe().cipher_modulus().value();
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
    /// Public-key contracts follow [`primus_tfhe_glwe::GlweEncryptionKey`].
    pub fn encryptor<'a, Key>(
        &'a self,
        key: &'a Key,
    ) -> Result<Encryptor<'a, T, Key>, TfheClientError>
    where
        Key: primus_tfhe_glwe::GlweEncryptionKey<
                T,
                primus_modulus::BarrettModulus<T>,
                primus_modulus::BarrettModulus<T>,
            >,
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

    /// Creates a Boolean encryptor for a secret or public key, requiring `t = 4`.
    /// Public-key contracts follow [`primus_tfhe_glwe::GlweEncryptionKey`].
    pub fn boolean_encryptor<'a, Key>(
        &'a self,
        key: &'a Key,
    ) -> Result<BooleanEncryptor<'a, T, Key>, BooleanError>
    where
        Key: primus_tfhe_glwe::GlweEncryptionKey<
                T,
                primus_modulus::BarrettModulus<T>,
                primus_modulus::BarrettModulus<T>,
            >,
    {
        BooleanEncryptor::new(&self.parameters, key)
    }

    /// Creates a Boolean decryptor after checking `t = 4` and the client key.
    pub fn boolean_decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<BooleanDecryptor<'a, T>, BooleanError> {
        BooleanDecryptor::new(&self.parameters, client_key)
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

    /// Compiles a unary function on `0..ceil(t/2)` into a lookup-table polynomial.
    #[inline]
    pub fn compile_lookup_table_fn<F>(
        &self,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        self.parameters.compile_lookup_table_fn(function)
    }

    /// Compiles one output per input in `0..ceil(t/2)` into a lookup-table polynomial.
    #[inline]
    pub fn compile_lookup_table_slice(
        &self,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError> {
        self.parameters.compile_lookup_table_slice(outputs)
    }

    /// Compiles several functions on `0..ceil(t/2)` into one PBSManyLUT accumulator.
    ///
    /// The output count must be nonzero, with
    /// `ceil(t/2) <= N / next_power_of_two(output_count)`. Function arguments are
    /// `(input, output_index)`; padding slots are filled with zero.
    /// See [`InterleavedLookupTable`] for the rotation-resolution tradeoff.
    #[inline]
    pub fn compile_interleaved_lookup_table_fn<F>(
        &self,
        output_count: usize,
        function: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        self.parameters
            .compile_interleaved_lookup_table_fn(output_count, function)
    }

    /// Compiles input-major multi-output values into one PBSManyLUT
    /// accumulator, ordered `[input][output_index]` for `0..ceil(t/2)` inputs.
    #[inline]
    pub fn compile_interleaved_lookup_table_slice(
        &self,
        output_count: usize,
        outputs: &[T],
    ) -> Result<InterleavedLookupTable<T>, LookupTableError> {
        self.parameters
            .compile_interleaved_lookup_table_slice(output_count, outputs)
    }

    /// Decomposes this context into its parameters and NTT table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
