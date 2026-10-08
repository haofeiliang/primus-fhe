use primus_integer::FheUint;
use primus_ntru::NtruCiphertext;
use primus_ntt::MonomialNttTable;

use crate::{LweCiphertext, PbsParameters, TfheContextError};

/// Validated binding between NTRU TFHE parameters and one exact NTT table.
pub struct TfheContext<T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    parameters: PbsParameters<T, LM>,
    table: Table,
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Builds the selected NTT table using the accumulator length and modulus.
    ///
    /// Preserves table-construction errors, including an unavailable primitive
    /// root or unsupported modulus. Use [`Self::try_new`] to inject an existing table.
    pub fn try_from_parameters(
        parameters: PbsParameters<T, LM>,
    ) -> Result<Self, TfheContextError<T>> {
        let accumulator = parameters.accumulator_ntru();
        let table = Table::new(accumulator.poly_length(), accumulator.cipher_modulus())?;
        Ok(Self { parameters, table })
    }

    /// Binds parameters to a compatible NTT table.
    pub fn try_new(
        parameters: PbsParameters<T, LM>,
        table: Table,
    ) -> Result<Self, TfheContextError<T>> {
        let expected = parameters.poly_length().get();
        let actual = table.poly_length().get();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        let expected = parameters.accumulator_ntru().cipher_modulus().value();
        let actual = table.modulus();
        if actual != expected {
            return Err(TfheContextError::ModulusMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated mathematical parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &PbsParameters<T, LM> {
        &self.parameters
    }

    /// Returns the bound NTT table.
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

    /// Allocates a zeroed coefficient-domain NTRU with the accumulator layout.
    /// Requires only public parameters; this does not encrypt a message.
    #[must_use]
    pub fn allocate_accumulator_ciphertext(&self) -> NtruCiphertext<Vec<T>> {
        NtruCiphertext::zero(self.parameters.accumulator_ntru().poly_length().get())
    }

    /// Decomposes this context into parameters and its NTT table.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (PbsParameters<T, LM>, Table) {
        (self.parameters, self.table)
    }
}
