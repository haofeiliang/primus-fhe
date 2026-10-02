use primus_glwe::GlweCiphertext;
use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;

use crate::{LweCiphertext, TfheContextError, TfheParameters};

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
    /// Builds the selected NTT table using the accumulator length and modulus.
    ///
    /// Preserves table-construction errors, including an unavailable primitive
    /// root or unsupported modulus. Use [`Self::try_new`] to inject an existing table.
    pub fn try_from_parameters(parameters: TfheParameters<T>) -> Result<Self, TfheContextError<T>> {
        let accumulator = parameters.accumulator_glwe();
        let table = Table::new(accumulator.poly_length(), accumulator.cipher_modulus())?;
        Ok(Self { parameters, table })
    }

    /// Binds TFHE parameters to a compatible NTT table.
    pub fn try_new(
        parameters: TfheParameters<T>,
        table: Table,
    ) -> Result<Self, TfheContextError<T>> {
        let expected = parameters.accumulator_glwe().poly_length().get();
        let actual = table.poly_length().get();
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
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the immutable NTT table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Allocates zero storage for an external LWE ciphertext (mask and body).
    /// Uses the dimension selected by the parameters; no key or encryption is involved.
    #[must_use]
    pub fn allocate_lwe_ciphertext(&self) -> LweCiphertext<T> {
        LweCiphertext::zero(self.parameters.external_lwe_dimension().get())
    }

    /// Allocates a zeroed coefficient-domain GLWE with the accumulator layout.
    /// Requires only public parameters; this does not encrypt a message.
    #[must_use]
    pub fn allocate_accumulator_ciphertext(&self) -> GlweCiphertext<Vec<T>> {
        GlweCiphertext::zero(self.parameters.accumulator_glwe().glwe_len())
    }

    /// Decomposes this context into its parameters and NTT table.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
