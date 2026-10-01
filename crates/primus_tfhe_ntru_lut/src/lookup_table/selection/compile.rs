//! Construction-only graph interning, selector assignment and slot scheduling.

use std::collections::HashMap;

use super::super::{Layout, PolynomialId};
use super::{
    OutputAction, OutputSelection, SelectionNode, SelectionPlan, SelectorBatches, TableNodeId,
    TableOperation,
};

/// A temporary source keeps unlifted public leaves separate from encrypted nodes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    PublicPolynomial(PolynomialId),
    Node(TableNodeId),
}

/// Construction-only interning across layers and outputs. Full operation equality
/// handles hash collisions; no hash map is retained by the compiled table.
pub(in crate::lookup_table) struct SelectionCompiler {
    layout: Layout,
    operations: Vec<TableOperation>,
    operation_ids: HashMap<TableOperation, TableNodeId>,
    output_roots: Vec<TableNodeId>,
}

impl SelectionCompiler {
    /// Starts an empty graph for one validated geometry and polynomial pool.
    pub fn new(layout: Layout) -> Self {
        Self {
            layout,
            operations: Vec::new(),
            operation_ids: HashMap::new(),
            output_roots: Vec::new(),
        }
    }

    /// Reduces one complete prefix array, preserving the fixed input-chunk order.
    /// All-equal groups pass their source through. A mixed group lifts its public
    /// leaves before encrypted selection; NLEV never controls an encrypted child.
    pub fn add_output(&mut self, polynomial_ids: Vec<PolynomialId>) {
        debug_assert_eq!(polynomial_ids.len(), self.layout.polynomials_per_output);
        let mut sources: Vec<_> = polynomial_ids
            .into_iter()
            .map(Source::PublicPolynomial)
            .collect();
        for chunk_index in
            self.layout.config.coefficient_chunk_count..self.layout.config.input_chunk_count
        {
            sources = sources
                .chunks_exact(self.layout.radix)
                .map(|group| self.reduce_group(chunk_index, group))
                .collect();
        }
        debug_assert_eq!(sources.len(), 1);
        let root = self.encrypted_node_id(sources[0]);
        self.output_roots.push(root);
    }

    /// Collapses identical branches or classifies a choice by its operand domain.
    /// A mixture of public and encrypted sources always requires NGSW selection.
    fn reduce_group(&mut self, chunk_index: usize, group: &[Source]) -> Source {
        if group.iter().all(|source| *source == group[0]) {
            return group[0];
        }
        let public: Option<Box<[PolynomialId]>> = group
            .iter()
            .map(|source| match source {
                Source::PublicPolynomial(polynomial_id) => Some(*polynomial_id),
                Source::Node(_) => None,
            })
            .collect();
        let operation = match public {
            Some(polynomial_ids) => TableOperation::SelectPublic {
                chunk_index,
                polynomial_ids,
            },
            None => TableOperation::SelectEncrypted {
                chunk_index,
                children: group
                    .iter()
                    .map(|&source| self.encrypted_node_id(source))
                    .collect(),
            },
        };
        Source::Node(self.get_or_insert_node(operation))
    }

    /// Converts a public source to an explicit initializer lift, shared by ID.
    fn encrypted_node_id(&mut self, source: Source) -> TableNodeId {
        match source {
            Source::PublicPolynomial(polynomial_id) => {
                self.get_or_insert_node(TableOperation::Lift(polynomial_id))
            }
            Source::Node(node_id) => node_id,
        }
    }

    /// Reuses only identical operations, including chunk identity and branch order.
    fn get_or_insert_node(&mut self, operation: TableOperation) -> TableNodeId {
        if let Some(&node_id) = self.operation_ids.get(&operation) {
            return node_id;
        }
        let node_id = TableNodeId(self.operations.len());
        self.operation_ids.insert(operation.clone(), node_id);
        self.operations.push(operation);
        node_id
    }

    /// Assigns selector batches, then fixes output order and live-result slots.
    /// DFS and last-use accounting stay together: writing a parent may reuse a
    /// child slot only after every operand has been read into separate scratch.
    pub fn finish(self) -> SelectionPlan {
        let (selectors, nlev_batch_count, ngsw_batch_count) = self.assign_selector_batches();
        drop(self.operation_ids);
        let mut schedule = SlotSchedule::new(&self.operations, &self.output_roots);
        let outputs = schedule.schedule_outputs(&self.operations, &self.output_roots);
        debug_assert_eq!(schedule.node_order.len(), self.operations.len());
        let nodes = self
            .operations
            .into_iter()
            .zip(schedule.assigned_slots)
            .map(|(operation, slot)| SelectionNode {
                operation,
                result_slot: slot.expect("reachable selection node"),
            })
            .collect();
        SelectionPlan {
            nodes,
            node_order: schedule.node_order.into_boxed_slice(),
            outputs,
            selectors,
            nlev_batch_count,
            ngsw_batch_count,
            result_slot_count: schedule.result_slot_count,
        }
    }

    /// Unions each high chunk's requirements in operation-insertion order.
    /// NLEV and NGSW have independent packed buffers and therefore independent
    /// batch numbering, even when a chunk uses both representations.
    fn assign_selector_batches(&self) -> (Box<[SelectorBatches]>, usize, usize) {
        let mut selectors = vec![SelectorBatches::Unused; self.layout.table_chunk_count()];
        let mut nlev_batch_count = 0;
        let mut ngsw_batch_count = 0;
        let first_chunk = self.layout.config.coefficient_chunk_count;
        for operation in &self.operations {
            match operation {
                TableOperation::Lift(_) => {}
                TableOperation::SelectPublic { chunk_index, .. } => {
                    selectors[chunk_index - first_chunk].require_nlev(&mut nlev_batch_count);
                }
                TableOperation::SelectEncrypted { chunk_index, .. } => {
                    selectors[chunk_index - first_chunk].require_ngsw(&mut ngsw_batch_count);
                }
            }
        }
        (
            selectors.into_boxed_slice(),
            nlev_batch_count,
            ngsw_batch_count,
        )
    }
}

impl SelectorBatches {
    /// Allocates a full selector batch only at its first public use.
    fn require_nlev(&mut self, count: &mut usize) {
        *self = match *self {
            Self::Unused => Self::Nlev(next_batch(count)),
            Self::Ngsw(ngsw) => Self::Both {
                nlev: next_batch(count),
                ngsw,
            },
            existing => existing,
        };
    }

    /// Allocates a compact selector batch only at its first encrypted use.
    fn require_ngsw(&mut self, count: &mut usize) {
        *self = match *self {
            Self::Unused => Self::Ngsw(next_batch(count)),
            Self::Nlev(nlev) => Self::Both {
                nlev,
                ngsw: next_batch(count),
            },
            existing => existing,
        };
    }
}

fn next_batch(count: &mut usize) -> usize {
    let batch = *count;
    *count += 1;
    batch
}

/// Construction-only liveness accounting. Child slots can become destinations
/// because every kernel finishes reading all branches before writing its slot.
struct SlotSchedule {
    remaining_uses: Vec<usize>,
    assigned_slots: Vec<Option<usize>>,
    free_slots: Vec<usize>,
    node_order: Vec<TableNodeId>,
    result_slot_count: usize,
}

impl SlotSchedule {
    /// Schedules each root once and separately marks complete-output reuse.
    /// Consuming a root does not modify its stored ciphertext: evaluation copies
    /// it to `current` before rotation, preserving any later child/root use.
    fn schedule_outputs(
        &mut self,
        operations: &[TableOperation],
        roots: &[TableNodeId],
    ) -> Box<[OutputSelection]> {
        let mut first_output = HashMap::new();
        roots
            .iter()
            .enumerate()
            .map(|(index, &root)| {
                let first = self.node_order.len();
                self.schedule_node(root, operations);
                let node_range = first..self.node_order.len();
                self.consume_use(root);
                let action = match first_output.get(&root) {
                    Some(&previous) => OutputAction::CopyFrom(previous),
                    None => {
                        first_output.insert(root, index);
                        OutputAction::Evaluate
                    }
                };
                debug_assert!(action == OutputAction::Evaluate || node_range.is_empty());
                OutputSelection {
                    node_range,
                    root,
                    action,
                }
            })
            .collect()
    }

    /// Counts every edge occurrence and output use, including repeated branches.
    fn new(operations: &[TableOperation], roots: &[TableNodeId]) -> Self {
        let mut remaining_uses = vec![0; operations.len()];
        for operation in operations {
            if let TableOperation::SelectEncrypted { children, .. } = operation {
                for &child in children {
                    remaining_uses[child.0] += 1;
                }
            }
        }
        for &root in roots {
            remaining_uses[root.0] += 1;
        }
        Self {
            remaining_uses,
            assigned_slots: vec![None; operations.len()],
            free_slots: Vec::new(),
            node_order: Vec::new(),
            result_slot_count: 0,
        }
    }

    /// Emits children before their parent, reusing destinations only after last use.
    fn schedule_node(&mut self, node_id: TableNodeId, operations: &[TableOperation]) {
        if self.assigned_slots[node_id.0].is_some() {
            return;
        }
        if let TableOperation::SelectEncrypted { children, .. } = &operations[node_id.0] {
            for &child in children {
                self.schedule_node(child, operations);
            }
            for &child in children {
                self.consume_use(child);
            }
        }
        let slot = self.free_slots.pop().unwrap_or_else(|| {
            let slot = self.result_slot_count;
            self.result_slot_count += 1;
            slot
        });
        self.assigned_slots[node_id.0] = Some(slot);
        self.node_order.push(node_id);
    }

    /// Drops one use, making the assigned slot available exactly once at zero.
    fn consume_use(&mut self, node_id: TableNodeId) {
        debug_assert!(self.remaining_uses[node_id.0] > 0);
        self.remaining_uses[node_id.0] -= 1;
        if self.remaining_uses[node_id.0] == 0 {
            self.free_slots
                .push(self.assigned_slots[node_id.0].expect("scheduled selection child"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        OutputAction, PolynomialId, SelectionCompiler, SelectorBatches, TableNodeId, TableOperation,
    };
    use crate::LookupTableConfig;

    // Symbolic polynomial IDs isolate compiler identity and slot liveness from
    // cryptographic noise. A parent output precedes its child outputs, so an
    // empty node range must still Evaluate. Prefix access is checked separately.
    #[test]
    fn shared_choices_preserve_chunk_identity_and_live_slots() {
        let layout = super::Layout::try_new(
            4u64,
            64,
            LookupTableConfig {
                input_chunk_count: 4,
                output_chunk_count: 6,
                coefficient_chunk_count: 1,
            },
        )
        .unwrap();
        let rows: Vec<Vec<PolynomialId>> = (0..6)
            .map(|output| {
                (0..8)
                    .map(|prefix| {
                        let a = prefix & 1;
                        let b = prefix >> 1 & 1;
                        let c = prefix >> 2 & 1;
                        PolynomialId(match output {
                            0 | 4 => {
                                if c == 0 {
                                    a
                                } else {
                                    b
                                }
                            }
                            1 => a,
                            2 => b,
                            3 => a & b,
                            _ => a ^ c,
                        })
                    })
                    .collect()
            })
            .collect();
        let mut compiler = SelectionCompiler::new(layout);
        for row in &rows {
            compiler.add_output(row.clone());
        }
        let plan = compiler.finish();
        assert_ne!(plan.outputs[1].root, plan.outputs[2].root);
        assert_eq!(plan.outputs[0].root, plan.outputs[4].root);
        assert!(plan.outputs[1].node_range.is_empty());
        assert_eq!(plan.outputs[1].action, OutputAction::Evaluate);
        assert!(plan.outputs[4].node_range.is_empty());
        assert_eq!(plan.outputs[4].action, OutputAction::CopyFrom(0));
        // The tile includes outputs with precomputed roots, stops before a copy,
        // and can resume after it. A small capacity must still limit the range.
        assert_eq!(plan.evaluation_tile(0, 8), 0..4);
        assert_eq!(plan.evaluation_tile(0, 2), 0..2);
        assert_eq!(plan.evaluation_tile(5, 8), 5..6);
        assert!(matches!(plan.selectors[1], SelectorBatches::Both { .. }));
        assert_eq!(plan.nodes.len(), 7); // Three public choices, three CMuxes, one lift.
        assert_eq!(plan.result_slot_count, 3);
        for prefix in 0..8 {
            let mut storage: Vec<Option<(TableNodeId, PolynomialId)>> =
                vec![None; plan.result_slot_count];
            for (output, row) in plan.outputs.iter().zip(&rows) {
                for &node_id in &plan.node_order[output.node_range.clone()] {
                    let node = plan.node(node_id);
                    let branch = |chunk_index: usize| prefix >> (chunk_index - 1) & 1;
                    let polynomial_id = match &node.operation {
                        TableOperation::Lift(polynomial_id) => *polynomial_id,
                        TableOperation::SelectPublic {
                            chunk_index,
                            polynomial_ids,
                        } => polynomial_ids[branch(*chunk_index)],
                        TableOperation::SelectEncrypted {
                            chunk_index,
                            children,
                        } => {
                            // Even unselected branches are read by CMux. Their
                            // live identities must survive destination reuse.
                            for &child in children {
                                assert_eq!(storage[plan.node(child).result_slot].unwrap().0, child);
                            }
                            storage[plan.node(children[branch(*chunk_index)]).result_slot]
                                .unwrap()
                                .1
                        }
                    };
                    storage[node.result_slot] = Some((node_id, polynomial_id));
                }
                assert_eq!(
                    storage[plan.node(output.root).result_slot],
                    Some((output.root, row[prefix]))
                );
            }
            for (output, row) in rows.iter().enumerate() {
                assert_eq!(
                    plan.resolve_polynomial_id(layout, output, prefix),
                    row[prefix]
                );
            }
        }
    }
}
