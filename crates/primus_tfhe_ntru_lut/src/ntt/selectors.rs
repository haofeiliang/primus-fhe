//! Selector destinations borrowed independently of the one-hot evaluator.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;
use primus_ntru::NttNgswCiphertext;
use primus_ntt::MonomialNttTable;
use primus_poly::PolynomialIterMut;
use primus_reduce::RingContext;
use primus_tfhe_ntru::CbsGadgetParameters;
use primus_tfhe_ntru_ntt::TfheContext;

use super::aggregate_rotation_control_to;
use crate::lookup_table::{
    Layout,
    selection::{SelectorBatches, SelectorChunk},
};

/// Mutable selector buffers only. This view lets a scoped BR projection feed
/// a chunk's consumer before the next projection reuses the same scratch.
/// The evaluator owns allocation and the compiled plan owns exact batch lengths.
pub(super) struct SelectorBuffers<'s, T> {
    pub public: &'s mut [T],
    pub encrypted: &'s mut [T],
    pub rotations: &'s mut [T],
    pub nonzero: &'s mut [T],
}

impl<T: FheUint> SelectorBuffers<'_, T> {
    /// Projects the chunk's required forms once, then converts or consumes those
    /// outputs. Rotation chunks retain only their monomial control; table chunks
    /// keep their assigned full NLEV and/or nonzero NGSW batches. The callback may
    /// perform a serial BR or consume an already prepared member of a pair.
    pub fn project_chunk<Table: MonomialNttTable<ValueT = T>, LM: RingContext<T>>(
        &mut self,
        chunk: SelectorChunk,
        layout: Layout,
        rotation_factors: &[T],
        parameters: &CbsGadgetParameters<T, BarrettModulus<T>>,
        context: &TfheContext<T, Table, LM>,
        project: impl FnOnce(Option<&mut [T]>, Option<&mut [T]>),
    ) {
        let selector_len = parameters.output_nlev_len();
        let full_len = layout.radix * selector_len;
        let nonzero_len = full_len - selector_len;
        let batches = match chunk {
            SelectorChunk::Rotation(index) => {
                project(None, Some(&mut *self.nonzero));
                let factor_len = (layout.radix - 1) * layout.polynomial_length;
                aggregate_rotation_control_to(
                    self.nonzero,
                    &rotation_factors[index * factor_len..(index + 1) * factor_len],
                    &mut NttNgswCiphertext::new(
                        &mut self.rotations[index * selector_len..(index + 1) * selector_len],
                    ),
                    parameters,
                    context.parameters().accumulator_ntru().cipher_modulus(),
                );
                return;
            }
            SelectorChunk::Table { batches, .. } => batches,
        };
        let (nlev, ngsw) = match batches {
            SelectorBatches::Unused => return,
            SelectorBatches::Nlev(_) => {
                (Some(&mut self.public[batches.nlev_range(full_len)]), None)
            }
            SelectorBatches::Ngsw(_) => (
                None,
                Some(&mut self.encrypted[batches.ngsw_range(nonzero_len)]),
            ),
            SelectorBatches::Both { .. } => (
                Some(&mut self.public[batches.nlev_range(full_len)]),
                Some(&mut self.encrypted[batches.ngsw_range(nonzero_len)]),
            ),
        };
        project(nlev, ngsw);
        if matches!(
            batches,
            SelectorBatches::Nlev(_) | SelectorBatches::Both { .. }
        ) {
            // NLEV projection writes coefficients; public products consume NTT rows.
            // Each required full batch is transformed once, including mixed roles.
            for row in PolynomialIterMut::new(
                &mut self.public[batches.nlev_range(full_len)],
                layout.polynomial_length,
            ) {
                context.table().transform_slice(row.0);
            }
        }
    }
}
