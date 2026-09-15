use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_tfhe::LookupTable;
use primus_tfhe::ManyLookupTable;
use primus_tfhe_glwe::GlweClientKey as ClientKey;

use crate::{
    Decryptor, Encryptor, Evaluator, KeyGenerator, ServerKey, TfheParameters,
    error::{
        LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    },
};

/// A validated binding between native-torus TFHE parameters and an FFT table.
///
/// The table is immutable and may be shared with any number of independent
/// [`FftEngine`] instances. Transform scratch is deliberately not stored in
/// this context.
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
    /// Binds TFHE parameters to a compatible Fourier table.
    pub fn try_new(parameters: TfheParameters<T>, table: Table) -> Result<Self, TfheContextError> {
        let expected = parameters.glwe().poly_length();
        let actual = table.poly_length();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated TFHE parameters.
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the immutable Fourier table.
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Creates an FFT engine with an independent backend scratch allocation.
    #[inline]
    pub fn new_fft_engine(&self) -> FftEngine<'_, Table> {
        FftEngine::new(&self.table)
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
                primus_modulus::NativeModulus<T>,
                primus_modulus::NativeModulus<T>,
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

    /// Creates a programmable-bootstrap evaluator with reusable FFT workspace.
    ///
    /// Inherits [`Evaluator::try_new`]'s Fourier table identity requirement.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
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

    /// Decomposes this context into its parameters and Fourier table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
