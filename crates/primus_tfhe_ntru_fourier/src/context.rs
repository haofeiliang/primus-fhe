use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_tfhe::ManyLookupTable;

use crate::{
    ClientKey, Decryptor, Encryptor, Evaluator, KeyGenerator, LookupTable, LookupTableError,
    ServerKey, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameters,
};

/// Validated binding between native NTRU TFHE parameters and one Fourier table.
pub struct TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    parameters: TfheParameters<T>,
    table: Table,
}

impl<T, Table> TfheContext<T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Binds parameters to a Fourier table with the same ring length.
    pub fn try_new(parameters: TfheParameters<T>, table: Table) -> Result<Self, TfheContextError> {
        let expected = parameters.poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated mathematical parameters.
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the immutable Fourier table.
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Creates an FFT engine with independent reusable backend scratch.
    #[inline]
    pub fn new_fft_engine(&self) -> FftEngine<'_, Table> {
        FftEngine::new(&self.table)
    }

    /// Generates a fresh client/server key pair.
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
    /// Public-key contracts follow [`primus_tfhe_ntru::NtruEncryptionKey`].
    pub fn encryptor<'a, Key>(
        &'a self,
        key: &'a Key,
    ) -> Result<Encryptor<'a, T, Key>, TfheClientError>
    where
        Key: primus_tfhe_ntru::NtruEncryptionKey<T, primus_modulus::NativeModulus<T>>,
    {
        Encryptor::try_new(&self.parameters, key)
    }

    /// Creates a client decryptor after checking the key once.
    pub fn decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T>, TfheClientError> {
        Decryptor::try_new(&self.parameters, client_key)
    }

    /// Creates an evaluator with reusable FFT and coefficient workspaces.
    /// The key must use this context's FFT table instance; see
    /// [`Evaluator::try_new`]'s correctness requirements.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }

    /// Generates optional CBS material under this client's accumulator secret.
    /// Inherits [`KeyGenerator::try_generate_circuit_bootstrap_key`]'s contracts.
    pub fn generate_circuit_bootstrap_key<R: rand::Rng + rand::CryptoRng>(
        &self,
        client_key: &ClientKey<T>,
        parameters: &crate::CircuitBootstrapParameters<T>,
        rng: &mut R,
    ) -> Result<crate::CircuitBootstrapKey<T>, crate::CircuitBootstrapKeyError> {
        KeyGenerator::new(self).try_generate_circuit_bootstrap_key(client_key, parameters, rng)
    }

    /// Binds an allocation-free online CBS evaluator to ordinary and optional keys.
    /// Inherits [`crate::CircuitBootstrapEvaluator::try_new`]'s key-identity contract.
    pub fn circuit_bootstrap_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
        parameters: &'a crate::CircuitBootstrapParameters<T>,
        circuit_key: &'a crate::CircuitBootstrapKey<T>,
    ) -> Result<
        crate::CircuitBootstrapEvaluator<'a, T, Table>,
        crate::CircuitBootstrapEvaluationError,
    > {
        crate::CircuitBootstrapEvaluator::try_new(self, server_key, parameters, circuit_key)
    }

    /// Compiles a unary function into a negacyclic lookup-table polynomial.
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

    /// Compiles one output for each programmable front-half input.
    #[inline]
    pub fn compile_lookup_table_slice(
        &self,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError> {
        self.parameters.compile_lookup_table_slice(outputs)
    }

    /// Compiles several functions on `0..ceil(t/2)` into one PBSManyLUT accumulator.
    ///
    /// The output count must be a non-zero power of two with
    /// `ceil(t/2) <= N / output_count`. Function arguments are `(input, output_index)`.
    /// See [`ManyLookupTable`] for the rotation-resolution tradeoff.
    #[inline]
    pub fn compile_many_lookup_table_fn<F>(
        &self,
        output_count: usize,
        function: F,
    ) -> Result<ManyLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        self.parameters
            .compile_many_lookup_table_fn(output_count, function)
    }

    /// Compiles input-major multi-output values into one PBSManyLUT
    /// accumulator, ordered `[input][output_index]` for `0..ceil(t/2)` inputs.
    #[inline]
    pub fn compile_many_lookup_table_slice(
        &self,
        output_count: usize,
        outputs: &[T],
    ) -> Result<ManyLookupTable<T>, LookupTableError> {
        self.parameters
            .compile_many_lookup_table_slice(output_count, outputs)
    }

    /// Decomposes this context into parameters and its Fourier table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
