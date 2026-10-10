//! Checked allocation lengths for the enabled LUT evaluator representations.

use primus_decompose::DecompositionLevelCount;
use primus_integer::FheUint;

use super::{HighPrecisionLookupTable, LookupTableError, checked_allocation_len};

impl<T: FheUint> HighPrecisionLookupTable<T> {
    /// NTT stores N ring elements per transformed polynomial.
    #[cfg(feature = "ntt")]
    pub(crate) fn ntt_buffer_lengths(
        &self,
        levels: DecompositionLevelCount,
    ) -> Result<BufferLengths, LookupTableError> {
        BufferLengths::try_new::<T, T>(self, levels, false)
    }

    /// Fourier stores N/2 complex values and retains coefficient conversion scratch.
    #[cfg(feature = "fourier")]
    pub(crate) fn fourier_buffer_lengths(
        &self,
        levels: DecompositionLevelCount,
    ) -> Result<BufferLengths, LookupTableError> {
        BufferLengths::try_new::<T, [f64; 2]>(self, levels, true)
    }
}

/// Checked element counts for buffers allocated directly by LUT evaluators.
/// Coefficient and transformed lengths use their actual storage element types.
pub(crate) struct BufferLengths {
    pub public_table_selectors: usize,
    pub encrypted_table_selectors: usize,
    pub rotation_controls: usize,
    pub nonzero_selectors: usize,
    pub rotation_factors: usize,
    pub selected_tables: usize,
    #[cfg(feature = "fourier")]
    pub public_selector_coefficients: usize,
    #[cfg(feature = "fourier")]
    pub gadget_one: usize,
}

impl BufferLengths {
    /// Checks each allocation in its actual storage element type before construction.
    /// Only the concrete NTT/Fourier helpers above choose V and representation.
    fn try_new<T: FheUint, V>(
        table: &HighPrecisionLookupTable<T>,
        levels: DecompositionLevelCount,
        fourier: bool,
    ) -> Result<Self, LookupTableError> {
        let layout = table.layout;
        let h = layout.table_chunk_count();
        let n = layout.polynomial_length;
        let row_len = if fourier { n / 2 } else { n };
        let d = layout.config.coefficient_chunk_count;
        let selector_len = checked_allocation_len::<V>(&[levels.get(), row_len])?;
        let nonzero_len = checked_allocation_len::<V>(&[layout.radix - 1, selector_len])?;
        Ok(Self {
            public_table_selectors: checked_allocation_len::<V>(&[
                usize::from(h > 0),
                layout.radix,
                selector_len,
            ])?,
            encrypted_table_selectors: checked_allocation_len::<V>(&[
                h.saturating_sub(1),
                nonzero_len,
            ])?,
            rotation_controls: checked_allocation_len::<V>(&[d, selector_len])?,
            nonzero_selectors: if d > 0 { nonzero_len } else { 0 },
            rotation_factors: checked_allocation_len::<V>(&[d, layout.radix - 1, row_len])?,
            selected_tables: checked_allocation_len::<T>(&[h.saturating_sub(1), layout.radix, n])?,
            #[cfg(feature = "fourier")]
            public_selector_coefficients: if fourier && h > 0 {
                checked_allocation_len::<T>(&[layout.radix, levels.get(), n])?
            } else {
                0
            },
            #[cfg(feature = "fourier")]
            gadget_one: if fourier && d > 0 { selector_len } else { 0 },
        })
    }
}
