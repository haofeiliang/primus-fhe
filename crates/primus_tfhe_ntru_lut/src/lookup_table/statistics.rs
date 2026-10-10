//! Optional offline inspection of polynomial sharing and the compiled selection plan.

use primus_integer::FheUint;

use super::HighPrecisionLookupTable;
use super::selection::TableOperation;

/// Geometry and work remaining after polynomial sharing and choice pruning.
/// Counts describe one complete evaluation, with selectors shared across outputs.
/// They are not latency estimates or a noise/security budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LookupTableStats {
    /// Total unsigned input bits, tau*c.
    pub input_bits: u32,
    /// Total unsigned output bits, tau*o.
    pub output_bits: u32,
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

impl<T: FheUint> HighPrecisionLookupTable<T> {
    /// Summarizes this compiled function, including data-dependent pruning and sharing.
    /// Walks the plan without allocating; call during setup, not per evaluation.
    #[must_use]
    pub fn stats(&self) -> LookupTableStats {
        let layout = self.layout;
        let selection = &self.selection;
        let d = layout.config.coefficient_chunk_count;
        // Construction establishes the total widths and bounds the storage counts.
        LookupTableStats {
            input_bits: layout.input_bits,
            output_bits: layout.output_bits,
            logical_polynomial_count: layout.config.output_chunk_count
                * layout.polynomials_per_output,
            unique_polynomial_count: self.unique_polynomial_count(),
            one_hot_chunk_count: self.one_hot_chunk_count(),
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
}
