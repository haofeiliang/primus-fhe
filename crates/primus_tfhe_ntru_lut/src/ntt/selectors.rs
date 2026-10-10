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
use crate::{evaluation::SelectorOutput, lookup_table::Layout};

/// Mutable selector buffers only. This view lets a scoped BR projection feed
/// a chunk's consumer before the next projection reuses the same scratch.
/// Allocation lengths follow the fixed roles of the low and high input chunks.
pub(super) struct SelectorBuffers<'s, T> {
    pub public: &'s mut [T],
    pub encrypted: &'s mut [T],
    pub rotations: &'s mut [T],
    pub nonzero: &'s mut [T],
}

impl<T: FheUint> SelectorBuffers<'_, T> {
    /// Low chunks retain only their aggregated monomial controls. The first high
    /// chunk retains all M NLEVs; later high chunks retain M-1 NGSWs each.
    /// The callback performs a serial BR or consumes one prepared pair member.
    pub fn project_chunk<Table: MonomialNttTable<ValueT = T>, LM: RingContext<T>>(
        &mut self,
        index: usize,
        layout: Layout,
        rotation_factors: &[T],
        parameters: &CbsGadgetParameters<T, BarrettModulus<T>>,
        context: &TfheContext<T, Table, LM>,
        project: impl FnOnce(SelectorOutput<'_, T, T>),
    ) {
        let selector_len = parameters.output_nlev_len();
        let d = layout.config.coefficient_chunk_count;
        if index < d {
            project(SelectorOutput::Ngsw(self.nonzero));
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
        } else if index == d {
            project(SelectorOutput::Nlev(self.public));
            // Projection writes coefficients; every first-layer public group
            // reuses this single full batch in NTT representation.
            for row in PolynomialIterMut::new(self.public, layout.polynomial_length) {
                context.table().transform_slice(row.0);
            }
        } else {
            let batch = index - d - 1;
            let nonzero_len = (layout.radix - 1) * selector_len;
            project(SelectorOutput::Ngsw(
                &mut self.encrypted[batch * nonzero_len..(batch + 1) * nonzero_len],
            ));
        }
    }
}
