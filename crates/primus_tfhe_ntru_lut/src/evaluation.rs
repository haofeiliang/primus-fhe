//! Buffer access shared by the concrete evaluators. The selection plan stays
//! immutable; ciphertext writes and borrowed slot views belong to execution.

use primus_integer::FheUint;
use primus_ntru::NtruCiphertext;
use primus_tfhe::LweCiphertext;

use crate::lookup_table::selection::SelectionNode;

/// Copies an earlier completed LWE after request-wide dimension checks. The
/// compiled action guarantees `previous < index` and identical subsequent work.
pub(crate) fn copy_completed_output_to<T: FheUint>(
    previous: usize,
    index: usize,
    output: &mut [LweCiphertext<T>],
) {
    let (completed, remaining) = output.split_at_mut(index);
    remaining[0]
        .as_mut()
        .copy_from_slice(completed[previous].as_ref());
}

/// Borrows one possibly noncontiguous result slot without gathering a batch.
/// The schedule keeps every child live until its parent's kernel has read it.
pub(crate) fn selected_ciphertext<'a, T: FheUint>(
    node: &SelectionNode,
    selected_tables: &'a [T],
    polynomial_length: usize,
) -> NtruCiphertext<&'a [T]> {
    NtruCiphertext::new(&selected_tables[node.result_range(polynomial_length)])
}
