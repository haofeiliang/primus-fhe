//! Immutable table choices and execution metadata. Construction scratch lives
//! in `compile`; online evaluation only follows the precomputed order and slots.
//! Compiler-only builds retain the complete plan. Scheduling fields deliberately
//! have no runtime reader until an evaluator backend is enabled.

use std::ops::Range;

use super::{Layout, PolynomialId};

mod compile;
pub(super) use compile::SelectionCompiler;

/// Stable identity of an interned table operation, distinct from a public
/// polynomial ID, an execution-order position, or a reusable result slot.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct TableNodeId(usize);

/// Operation identity includes the input chunk and ordered branches. Every
/// result is a coefficient-form NTRU under f, with the table's ring/encoding.
#[derive(Clone, Hash, PartialEq, Eq)]
pub(crate) enum TableOperation {
    /// `NLEV[1]` lift of a public polynomial, using its separately bound basis.
    Lift(PolynomialId),
    /// Full NLEV selection lifts the M public polynomials under f.
    SelectPublic {
        chunk_index: usize,
        polynomial_ids: Box<[PolynomialId]>,
    },
    /// Nonzero NGSWs choose among M already lifted/encrypted children.
    SelectEncrypted {
        chunk_index: usize,
        children: Box<[TableNodeId]>,
    },
}

/// A shared result's destination remains valid until its compiled last use.
#[cfg_attr(not(any(feature = "ntt", feature = "fourier")), allow(dead_code))]
pub(crate) struct SelectionNode {
    pub operation: TableOperation,
    result_slot: usize,
}

#[cfg(any(feature = "ntt", feature = "fourier"))]
impl SelectionNode {
    /// Coefficient range in the evaluator's flat result pool. Slots need not
    /// follow node order; last-use scheduling can reuse a child's destination.
    pub fn result_range(&self, polynomial_length: usize) -> Range<usize> {
        let first = self.result_slot * polynomial_length;
        first..first + polynomial_length
    }
}

/// An empty node range can still require rotation and return: a previous
/// output may have computed this root as a child without returning it itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputAction {
    Evaluate,
    /// Same root and subsequent operations as this earlier, completed output.
    CopyFrom(usize),
}

/// Newly needed nodes and the unrotated root for one output. Ranges partition
/// the execution order; the action separately identifies completed-LWE reuse.
#[cfg_attr(not(any(feature = "ntt", feature = "fourier")), allow(dead_code))]
struct OutputSelection {
    node_range: Range<usize>,
    root: TableNodeId,
    action: OutputAction,
}

/// Batch indices in the two backend selector buffers. Pruning can leave one
/// high chunk used by public choices, encrypted choices, both, or neither.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub(crate) enum SelectorBatches {
    #[default]
    Unused,
    Nlev(usize),
    Ngsw(usize),
    Both {
        nlev: usize,
        ngsw: usize,
    },
}

/// One live input chunk and the mathematical use of its one-hot projection.
/// Table batches are assigned by the compiler; rotation controls use the low
/// chunk index. These small values are yielded on demand, never stored as jobs.
#[cfg(any(feature = "ntt", feature = "fourier"))]
#[derive(Clone, Copy)]
pub(crate) enum SelectorChunk {
    /// Aggregate the nonzero NGSWs into `NGSW[X^(-m_i*M^i)]` for low chunk i.
    Rotation(usize),
    /// Retain the full NLEV and/or nonzero NGSW batches needed by table choices.
    Table {
        chunk_index: usize,
        batches: SelectorBatches,
    },
}

#[cfg(any(feature = "ntt", feature = "fourier"))]
impl SelectorChunk {
    /// Index in the least-significant-chunk-first input, including pruned gaps.
    #[must_use]
    pub fn input_index(self) -> usize {
        match self {
            Self::Rotation(index) => index,
            Self::Table { chunk_index, .. } => chunk_index,
        }
    }
}

#[cfg(any(feature = "ntt", feature = "fourier"))]
impl SelectorBatches {
    /// Full-M NLEV batch for a compiled public choice. Its existence is fixed
    /// by the compiler, independently of the nonzero NGSW batch index.
    pub fn nlev_range(self, batch_len: usize) -> Range<usize> {
        let batch = match self {
            Self::Nlev(batch) | Self::Both { nlev: batch, .. } => batch,
            _ => panic!("public choice requires NLEV"),
        };
        batch * batch_len..(batch + 1) * batch_len
    }

    /// Compact M-1 NGSW batch for a compiled encrypted choice.
    pub fn ngsw_range(self, batch_len: usize) -> Range<usize> {
        let batch = match self {
            Self::Ngsw(batch) | Self::Both { ngsw: batch, .. } => batch,
            _ => panic!("encrypted choice requires NGSW"),
        };
        batch * batch_len..(batch + 1) * batch_len
    }
}

/// Immutable execution order and storage assignment. No structure discovery,
/// liveness accounting or ciphertext mutation belongs to this plan.
#[cfg_attr(not(any(feature = "ntt", feature = "fourier")), allow(dead_code))]
pub(crate) struct SelectionPlan {
    nodes: Box<[SelectionNode]>,
    node_order: Box<[TableNodeId]>,
    outputs: Box<[OutputSelection]>,
    /// High chunks in ascending order, with indices relative to the split d.
    pub selectors: Box<[SelectorBatches]>,
    pub nlev_batch_count: usize,
    pub ngsw_batch_count: usize,
    pub result_slot_count: usize,
}

impl SelectionPlan {
    /// Low rotation chunks followed by surviving high table chunks, in input
    /// order. Pruned gaps consume no projection or sparse-pair member. The caller
    /// supplies this table's split d; pairing and immediate consumption stay with
    /// the backend so projection scratch never outlives its current input.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    pub fn selector_chunks(
        &self,
        coefficient_chunk_count: usize,
    ) -> impl Iterator<Item = SelectorChunk> {
        let rotations = (0..coefficient_chunk_count).map(SelectorChunk::Rotation);
        let tables = self
            .selectors
            .iter()
            .enumerate()
            .filter_map(move |(index, &batches)| {
                (batches != SelectorBatches::Unused).then_some(SelectorChunk::Table {
                    chunk_index: coefficient_chunk_count + index,
                    batches,
                })
            });
        rotations.chain(tables)
    }

    /// Borrow reachable operations for setup-time cost inspection.
    pub(super) fn operations(&self) -> impl ExactSizeIterator<Item = &TableOperation> {
        self.nodes.iter().map(|node| &node.operation)
    }

    /// All compiled nodes are reachable; only explicit lifts need independent `NLEV[1]`.
    pub fn needs_public_lift(&self) -> bool {
        self.nodes
            .iter()
            .any(|node| matches!(node.operation, TableOperation::Lift(_)))
    }

    #[cfg(any(test, feature = "ntt", feature = "fourier"))]
    pub fn output_action(&self, index: usize) -> OutputAction {
        self.outputs[index].action
    }

    /// Consecutive outputs that need evaluation, bounded by return capacity.
    /// Stops before copying a repeated output: its source LWE must be completed
    /// by the preceding tile. The caller starts on Evaluate with nonzero capacity.
    #[cfg(any(test, feature = "fourier"))]
    pub fn evaluation_tile(&self, first: usize, capacity: usize) -> Range<usize> {
        debug_assert!(capacity > 0);
        debug_assert_eq!(self.output_action(first), OutputAction::Evaluate);
        let count = self.outputs[first..]
            .iter()
            .take(capacity)
            .take_while(|output| output.action == OutputAction::Evaluate)
            .count();
        first..first + count
    }

    /// Nodes not yet computed by earlier outputs, in dependency order.
    #[cfg(any(feature = "ntt", feature = "fourier"))]
    pub fn scheduled_nodes(&self, output: usize) -> impl ExactSizeIterator<Item = &SelectionNode> {
        self.node_order[self.outputs[output].node_range.clone()]
            .iter()
            .map(|&node_id| self.node(node_id))
    }

    #[must_use]
    pub fn node(&self, node_id: TableNodeId) -> &SelectionNode {
        &self.nodes[node_id.0]
    }

    #[cfg(any(feature = "ntt", feature = "fourier"))]
    pub fn root_node(&self, output: usize) -> &SelectionNode {
        self.node(self.outputs[output].root)
    }

    /// Resolves a logical prefix through reduced choices, without retaining a
    /// P-entry map per output. Digits of skipped chunks do not affect the result.
    pub fn resolve_polynomial_id(
        &self,
        layout: Layout,
        output: usize,
        prefix: usize,
    ) -> PolynomialId {
        let mut node_id = self.outputs[output].root;
        loop {
            let branch = |chunk_index| {
                (prefix
                    >> ((chunk_index - layout.config.coefficient_chunk_count) * layout.chunk_bits))
                    & (layout.radix - 1)
            };
            match &self.node(node_id).operation {
                TableOperation::Lift(polynomial_id) => return *polynomial_id,
                TableOperation::SelectPublic {
                    chunk_index,
                    polynomial_ids,
                } => {
                    return polynomial_ids[branch(*chunk_index)];
                }
                TableOperation::SelectEncrypted {
                    chunk_index,
                    children,
                } => node_id = children[branch(*chunk_index)],
            }
        }
    }
}
