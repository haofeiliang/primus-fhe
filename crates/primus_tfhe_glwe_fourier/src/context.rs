use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::GlweCiphertext;

use crate::{LweCiphertext, TfheContextError, TfheParameters};

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
    /// Builds the selected FFT table using the accumulator polynomial length.
    ///
    /// Use [`Self::try_new`] to inject an existing table instead; all transformed
    /// keys must use the bound table. The parameters already establish its length.
    #[must_use]
    pub fn from_parameters(parameters: TfheParameters<T>) -> Self {
        let table = Table::new(parameters.blind_rotation_ggsw().poly_length());
        Self { parameters, table }
    }

    /// Binds TFHE parameters to a compatible Fourier table.
    pub fn try_new(parameters: TfheParameters<T>, table: Table) -> Result<Self, TfheContextError> {
        let expected = parameters.blind_rotation_ggsw().poly_length().get();
        let actual = table.poly_length().get();
        if actual != expected {
            return Err(TfheContextError::PolynomialLengthMismatch { expected, actual });
        }
        Ok(Self { parameters, table })
    }

    /// Returns the validated TFHE parameters.
    #[must_use]
    #[inline]
    pub fn parameters(&self) -> &TfheParameters<T> {
        &self.parameters
    }

    /// Returns the immutable Fourier table.
    #[must_use]
    #[inline]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// Creates an FFT engine with an independent backend scratch allocation.
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

    /// Allocates a zeroed coefficient-domain GLWE with the accumulator layout.
    /// Requires only public parameters; this does not encrypt a message.
    #[must_use]
    pub fn allocate_accumulator_ciphertext(&self) -> GlweCiphertext<Vec<T>> {
        GlweCiphertext::zero(self.parameters.blind_rotation_ggsw().glwe_len())
    }

    /// Decomposes this context into its parameters and Fourier table.
    #[must_use]
    #[inline]
    pub fn into_parts(self) -> (TfheParameters<T>, Table) {
        (self.parameters, self.table)
    }
}
