use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_ntru::NtruCiphertext;

use crate::{LweCiphertext, TfheContextError, TfheParameters};

/// Validated binding between native NTRU TFHE parameters and one Fourier table.
pub struct TfheContext<T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    parameters: TfheParameters<T, LM>,
    table: Table,
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Builds the selected FFT table using the accumulator polynomial length.
    ///
    /// Use [`Self::try_new`] to inject an existing table instead; all transformed
    /// keys must use the bound table. The parameters already establish its length.
    #[must_use]
    pub fn from_parameters(parameters: TfheParameters<T, LM>) -> Self {
        let table = Table::new(parameters.accumulator_ntru().poly_length());
        Self { parameters, table }
    }

    /// Binds parameters to a Fourier table with the same ring length.
    pub fn try_new(
        parameters: TfheParameters<T, LM>,
        table: Table,
    ) -> Result<Self, TfheContextError> {
        let expected = parameters.poly_length().get();
        let actual = table.poly_length().get();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated mathematical parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T, LM> {
        &self.parameters
    }

    /// Returns the immutable Fourier table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Creates an FFT engine with independent reusable backend scratch.
    #[must_use]
    #[inline]
    pub fn new_fft_engine(&self) -> FftEngine<'_, Table> {
        FftEngine::new(&self.table)
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

    /// Decomposes this context into parameters and its Fourier table.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T, LM>, Table) {
        (self.parameters, self.table)
    }
}
