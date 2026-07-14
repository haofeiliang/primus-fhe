//! Fourier backend for GLWE-based TFHE.

use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;

mod evaluator;
mod key;

pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use primus_fhe_core::{
    BooleanCiphertext, BooleanError, BooleanGate, Ciphertext, ClientKey, LookupTable,
    LookupTableError, LweKeySwitchingParameters, TfheClientError, TfheEvaluationError,
    TfheKeyError, TfheParameterError,
};

/// Encryptor role for the native-torus Fourier backend.
///
/// Only client-key encryption is implemented currently; the key type is kept
/// generic so public-key encryption can be added without replacing this type.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_fhe_core::Encryptor<'a, T, NativeModulus<T>, Key>;

/// Client-key decryptor for the native-torus Fourier backend.
pub type Decryptor<'a, T> = primus_fhe_core::Decryptor<'a, T, NativeModulus<T>>;

/// Boolean encryptor for the native-torus Fourier backend.
pub type BooleanEncryptor<'a, T> = primus_fhe_core::BooleanEncryptor<'a, T, NativeModulus<T>>;

/// Boolean decryptor for the native-torus Fourier backend.
pub type BooleanDecryptor<'a, T> = primus_fhe_core::BooleanDecryptor<'a, T, NativeModulus<T>>;

/// Boolean gate evaluator backed by Fourier programmable bootstrapping.
pub type BooleanEvaluator<'a, T, Table> = primus_fhe_core::BooleanEvaluator<
    'a,
    T,
    NativeModulus<T>,
    NativeModulus<T>,
    Evaluator<'a, T, Table>,
>;

/// GLWE-TFHE parameters for the native-torus Fourier backend.
pub type TfheParameters<T> = primus_fhe_core::TfheParameters<T, NativeModulus<T>, NativeModulus<T>>;

/// An incompatibility between TFHE parameters and a Fourier table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheContextError {
    /// The Fourier table was built for a different polynomial length.
    #[error("FFT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the GLWE parameters.
        expected: usize,
        /// Polynomial length supported by the Fourier table.
        actual: usize,
    },
}

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

    /// Creates a Boolean gate evaluator with an independent FFT workspace.
    pub fn new_boolean_evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<BooleanEvaluator<'a, T, Table>, BooleanError> {
        let evaluator = Evaluator::try_new(self, server_key)?;
        primus_fhe_core::BooleanEvaluator::try_new(&self.parameters, evaluator)
    }

    /// Compiles a unary function into a coefficient-domain GLWE accumulator.
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

    /// Compiles one output per plaintext input into a GLWE accumulator.
    #[inline]
    pub fn compile_lookup_table_slice(
        &self,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError> {
        self.parameters.compile_lookup_table_slice(outputs)
    }

    /// Decomposes this context into its parameters and Fourier table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
