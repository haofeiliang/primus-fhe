//! NTT backend for GLWE-based TFHE.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntt::NttTable;

pub use primus_fhe_core::{LweKeySwitchingParameters, TfheParameterError};

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

    /// Decomposes this context into its parameters and NTT table.
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
