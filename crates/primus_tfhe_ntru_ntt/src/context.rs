use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_ntt::NttTable;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd};
use primus_tfhe::InterleavedLookupTable;

use crate::{
    ClientKey, Decryptor, Encryptor, Evaluator, KeyGenerator, LookupTable, LookupTableError,
    ServerKey, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameters,
};

/// Validated binding between NTRU TFHE parameters and one exact NTT table.
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
        let expected = parameters.bootstrapping().ntru().cipher_modulus().value();
        let actual = table.modulus();
        if actual != expected {
            return Err(TfheContextError::ModulusMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated mathematical parameters.
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the bound NTT table.
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
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
        Key: primus_tfhe_ntru::NtruEncryptionKey<T, primus_modulus::BarrettModulus<T>>,
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

    /// Creates an evaluator with reusable NTT and coefficient workspaces.
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

    /// See [`primus_tfhe_ntru::NtruTfheParameters::compile_lookup_table_fn`].
    #[inline]
    pub fn compile_lookup_table_fn<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        self.parameters
            .compile_lookup_table_fn(output_codec, function)
    }

    /// See [`primus_tfhe_ntru::NtruTfheParameters::compile_lookup_table_slice`].
    #[inline]
    pub fn compile_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        self.parameters
            .compile_lookup_table_slice(output_codec, outputs)
    }

    /// See [`primus_tfhe_ntru::NtruTfheParameters::compile_interleaved_lookup_table_fn`].
    #[inline]
    pub fn compile_interleaved_lookup_table_fn<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        function: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize, usize) -> T,
    {
        self.parameters
            .compile_interleaved_lookup_table_fn(output_codec, output_count, function)
    }

    /// See [`primus_tfhe_ntru::NtruTfheParameters::compile_interleaved_lookup_table_slice`].
    #[inline]
    pub fn compile_interleaved_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        outputs: &[T],
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        self.parameters
            .compile_interleaved_lookup_table_slice(output_codec, output_count, outputs)
    }

    /// Decomposes this context into parameters and its NTT table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
