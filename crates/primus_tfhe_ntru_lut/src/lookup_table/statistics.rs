//! Inspection of the compiled plan and lengths of buffers owned directly by LUT evaluators.

use primus_decompose::DecompositionLevelCount;
use primus_integer::FheUint;

use super::selection::{SelectorBatches, TableOperation};
use super::{HighPrecisionLookupTable, LookupTableError, checked_allocation_len};

/// Geometry and work remaining after polynomial sharing and choice pruning.
/// Counts describe one complete evaluation, with selectors shared across outputs.
/// They are not latency estimates or a noise/security budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupTableStats {
    /// Total unsigned input bits, tau*c.
    pub input_bits: usize,
    /// Total unsigned output bits, tau*o.
    pub output_bits: usize,
    /// Polynomial count across all outputs before deduplication, o*M^(c-d).
    pub logical_polynomial_count: usize,
    /// Number of stored N-coefficient polynomials after deduplication.
    pub unique_polynomial_count: usize,
    /// Input chunks needing one-hot CBS, including all d rotation chunks.
    /// A chunk needing both NLEV and NGSW shares one BR/projection pass.
    pub one_hot_chunk_count: usize,
    /// Full-M NLEV selectors generated for surviving public choices.
    pub nlev_selector_count: usize,
    /// Nonzero NGSW selectors generated for encrypted choices and low-chunk rotations.
    /// Rotation batches are generated one chunk at a time and reuse storage.
    pub ngsw_selector_count: usize,
    /// Shared selection nodes, including public lifts; each executes once per request.
    pub selection_node_count: usize,
    /// Explicit `NLEV[1]` lift nodes; zero means no independent public-lift material is needed.
    pub public_lift_count: usize,
    /// Simultaneously live coefficient NTRU slots assigned by the selection schedule.
    pub result_slot_count: usize,
}

/// Requested heap bytes for the buffers owned directly by each LUT evaluator.
/// Includes retained selectors, rotation controls/factors, selected-table slots,
/// current/product polynomials, and Fourier conversion/gadget-one buffers.
///
/// **Excludes** nested BR/CBS/one-hot and LWE-return workspaces, transform engines,
/// keys, public table/plan, caller inputs/outputs, allocator overhead and temporary
/// construction storage. This is a partial workspace estimate, not peak or total memory.
/// Both representations are available to compiler-only consumers without loading a backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupWorkspaceEstimate {
    /// NTT buffers use T-sized ring elements.
    pub ntt_bytes: usize,
    /// Fourier buffers use pairs of f64; coefficient buffers still use T.
    pub fourier_bytes: usize,
}

impl<T: FheUint> HighPrecisionLookupTable<T> {
    /// Summarizes this compiled function, including data-dependent pruning and sharing.
    /// Walks the plan without allocating; call during setup, not per evaluation.
    #[must_use]
    pub fn stats(&self) -> LookupTableStats {
        let layout = self.layout;
        let selection = &self.selection;
        let d = layout.config.coefficient_chunk_count;
        // Domain/storage construction bounds these counts and both bit products.
        LookupTableStats {
            input_bits: layout.chunk_bits * layout.config.input_chunk_count,
            output_bits: layout.chunk_bits * layout.config.output_chunk_count,
            logical_polynomial_count: layout.config.output_chunk_count
                * layout.polynomials_per_output,
            unique_polynomial_count: self.unique_polynomial_count(),
            one_hot_chunk_count: d + selection
                .selectors
                .iter()
                .filter(|&&batch| batch != SelectorBatches::Unused)
                .count(),
            nlev_selector_count: selection.nlev_batch_count * layout.radix,
            ngsw_selector_count: (d + selection.ngsw_batch_count) * (layout.radix - 1),
            selection_node_count: selection.operations().len(),
            public_lift_count: selection
                .operations()
                .filter(|op| matches!(op, TableOperation::Lift(_)))
                .count(),
            result_slot_count: selection.result_slot_count,
        }
    }

    /// Estimates the direct LUT buffers for a proposed CBS output level count L.
    /// Uses the same length calculations as evaluator construction. It does not
    /// validate a CBS basis or one-hot geometry; binding performs those checks.
    /// See [`LookupWorkspaceEstimate`] for the excluded resources.
    /// Returns [`LookupTableError::StorageSizeOverflow`] on buffer/byte overflow.
    pub fn estimate_workspace(
        &self,
        output_levels: DecompositionLevelCount,
    ) -> Result<LookupWorkspaceEstimate, LookupTableError> {
        Ok(LookupWorkspaceEstimate {
            ntt_bytes: self
                .ntt_buffer_lengths(output_levels)?
                .bytes::<T, T>(self.layout.polynomial_length)?,
            fourier_bytes: self
                .fourier_buffer_lengths(output_levels)?
                .bytes::<T, [f64; 2]>(self.layout.polynomial_length)?,
        })
    }

    /// NTT stores N ring elements per transformed polynomial.
    pub(crate) fn ntt_buffer_lengths(
        &self,
        levels: DecompositionLevelCount,
    ) -> Result<BufferLengths, LookupTableError> {
        BufferLengths::try_new::<T, T>(self, levels, false)
    }

    /// Fourier stores N/2 complex values and retains coefficient conversion scratch.
    pub(crate) fn fourier_buffer_lengths(
        &self,
        levels: DecompositionLevelCount,
    ) -> Result<BufferLengths, LookupTableError> {
        BufferLengths::try_new::<T, [f64; 2]>(self, levels, true)
    }
}

/// Element counts shared by allocation and the public estimate. Coefficient and
/// transformed lengths remain distinct; this describes no arithmetic operation.
pub(crate) struct BufferLengths {
    pub public_table_selectors: usize,
    pub encrypted_table_selectors: usize,
    pub rotation_controls: usize,
    pub nonzero_selectors: usize,
    pub rotation_factors: usize,
    pub selected_tables: usize,
    pub public_selector_coefficients: usize,
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
        let selection = &table.selection;
        let n = layout.polynomial_length;
        let row_len = if fourier { n / 2 } else { n };
        let d = layout.config.coefficient_chunk_count;
        let selector_len = checked_allocation_len::<V>(&[levels.get(), row_len])?;
        let nonzero_len = checked_allocation_len::<V>(&[layout.radix - 1, selector_len])?;
        Ok(Self {
            public_table_selectors: checked_allocation_len::<V>(&[
                selection.nlev_batch_count,
                layout.radix,
                selector_len,
            ])?,
            encrypted_table_selectors: checked_allocation_len::<V>(&[
                selection.ngsw_batch_count,
                nonzero_len,
            ])?,
            rotation_controls: checked_allocation_len::<V>(&[d, selector_len])?,
            nonzero_selectors: if d > 0 { nonzero_len } else { 0 },
            rotation_factors: checked_allocation_len::<V>(&[d, layout.radix - 1, row_len])?,
            selected_tables: checked_allocation_len::<T>(&[selection.result_slot_count, n])?,
            public_selector_coefficients: if fourier && selection.nlev_batch_count > 0 {
                checked_allocation_len::<T>(&[layout.radix, levels.get(), n])?
            } else {
                0
            },
            gadget_one: if fourier && d > 0 { selector_len } else { 0 },
        })
    }

    /// Sums separately checked buffers, including the two coefficient polynomials.
    /// No byte count includes the inline evaluator object or its nested resources.
    fn bytes<T, V>(&self, n: usize) -> Result<usize, LookupTableError> {
        let buffers = [
            (self.public_table_selectors, size_of::<V>()),
            (self.encrypted_table_selectors, size_of::<V>()),
            (self.rotation_controls, size_of::<V>()),
            (self.nonzero_selectors, size_of::<V>()),
            (self.rotation_factors, size_of::<V>()),
            (self.gadget_one, size_of::<V>()),
            (self.selected_tables, size_of::<T>()),
            (self.public_selector_coefficients, size_of::<T>()),
            (2 * n, size_of::<T>()),
        ];
        buffers.into_iter().try_fold(0usize, |total, (len, size)| {
            len.checked_mul(size)
                .and_then(|bytes| total.checked_add(bytes))
                .ok_or(LookupTableError::StorageSizeOverflow)
        })
    }
}
