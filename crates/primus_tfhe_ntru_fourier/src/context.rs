use primus_fft::{FftEngine, FftTable, TorusFftValue};

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
    pub fn generate_keys<R>(&self, rng: &mut R) -> Result<(ClientKey<T>, ServerKey), TfheKeyError>
    where
        R: rand::Rng + rand::CryptoRng,
    {
        KeyGenerator::new(self).generate(rng)
    }

    /// Creates a client encryptor after checking the key once.
    pub fn encryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Encryptor<'a, T>, TfheClientError> {
        Encryptor::new(&self.parameters, client_key)
    }

    /// Creates a client decryptor after checking the key once.
    pub fn decryptor<'a>(
        &'a self,
        client_key: &'a ClientKey<T>,
    ) -> Result<Decryptor<'a, T>, TfheClientError> {
        Decryptor::new(&self.parameters, client_key)
    }

    /// Creates an evaluator with reusable FFT and coefficient workspaces.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
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

    /// Decomposes this context into parameters and its Fourier table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
