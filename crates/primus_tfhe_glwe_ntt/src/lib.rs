//! NTT backend for GLWE-based TFHE.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;

mod key;

pub use key::{KeyGenerator, ServerKey};
pub use primus_fhe_core::{
    Ciphertext, ClientKey, LookupTable, LookupTableError, LweKeySwitchingParameters,
    TfheClientError, TfheKeyError, TfheParameterError,
};

/// Encryptor role for the explicit-modulus NTT backend.
///
/// Only client-key encryption is implemented currently; the key type is kept
/// generic so public-key encryption can be added without replacing this type.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_fhe_core::Encryptor<'a, T, BarrettModulus<T>, Key>;

/// Client-key decryptor for the explicit-modulus NTT backend.
pub type Decryptor<'a, T> = primus_fhe_core::Decryptor<'a, T, BarrettModulus<T>>;

/// GLWE-TFHE parameters for the explicit-modulus NTT backend.
pub type TfheParameters<T> =
    primus_fhe_core::TfheParameters<T, BarrettModulus<T>, BarrettModulus<T>>;

/// An incompatibility between TFHE parameters and an NTT table.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TfheContextError<T: FheUint> {
    /// The NTT table was built for a different polynomial length.
    #[error("NTT polynomial length mismatch: expected {expected}, got {actual}")]
    PolynomialLengthMismatch {
        /// Polynomial length required by the GLWE parameters.
        expected: usize,
        /// Polynomial length supported by the NTT table.
        actual: usize,
    },

    /// The NTT table was built for a different coefficient modulus.
    #[error("NTT modulus mismatch: expected {expected:?}, got {actual:?}")]
    ModulusMismatch {
        /// Coefficient modulus required by the GLWE parameters.
        expected: T,
        /// Coefficient modulus supported by the NTT table.
        actual: T,
    },

    /// The current LWE key-switching implementation requires the small-LWE
    /// and sample-extracted GLWE ciphertexts to use the same modulus.
    #[error("LWE/GLWE ciphertext modulus mismatch: LWE uses {lwe:?}, GLWE uses {glwe:?}")]
    CiphertextModulusMismatch {
        /// Small-LWE ciphertext modulus.
        lwe: T,
        /// GLWE ciphertext modulus.
        glwe: T,
    },
}

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

        let expected = parameters.glwe().cipher_modulus_value();
        let actual = table.modulus();
        if actual != expected {
            return Err(TfheContextError::ModulusMismatch { expected, actual });
        }

        let lwe = parameters.lwe().cipher_modulus().value();
        if lwe != expected {
            return Err(TfheContextError::CiphertextModulusMismatch {
                lwe,
                glwe: expected,
            });
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

    /// Decomposes this context into its parameters and NTT table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
