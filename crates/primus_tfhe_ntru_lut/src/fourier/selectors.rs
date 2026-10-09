//! Selector destinations and constants borrowed independently of one-hot CBS.

use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::nlev::{FourierNlevIterMut, NlevIter};
use primus_modulus::NativeModulus;
use primus_ntru::FourierNgswCiphertext;
use primus_tfhe_ntru::CbsGadgetParameters;

use super::aggregate_rotation_control_to;
use crate::lookup_table::{
    Layout,
    selection::{SelectorBatches, SelectorChunk},
};

/// Borrowed destinations and immutable rotation constants. Projection and its
/// consumer finish before the next input reuses the coefficient/nonzero scratch.
/// The evaluator owns allocation; the compiled plan owns exact batch lengths.
pub(super) struct SelectorBuffers<'s, T> {
    pub public: &'s mut [Complex64],
    pub coefficients: &'s mut [T],
    pub encrypted: &'s mut [Complex64],
    pub rotations: &'s mut [Complex64],
    pub nonzero: &'s mut [Complex64],
    pub rotation_factors: &'s [Complex64],
    pub gadget_one: &'s [Complex64],
}

impl<T: TorusFftValue> SelectorBuffers<'_, T> {
    /// Projects a low rotation control or the surviving high-chunk selectors.
    /// The callback performs a serial BR or consumes one prepared pair member;
    /// it then lends the shared FFT engine for immediate coefficient conversion.
    pub fn project_chunk<'f, 'a: 'f, Table: FftTable + 'a>(
        &mut self,
        chunk: SelectorChunk,
        layout: Layout,
        parameters: &CbsGadgetParameters<T, NativeModulus<T>>,
        project: impl FnOnce(Option<&mut [T]>, Option<&mut [Complex64]>) -> &'f mut FftEngine<'a, Table>,
    ) {
        let selector_len = parameters.output_nlev_len() / 2;
        let full_len = layout.radix * selector_len;
        let nonzero_len = full_len - selector_len;
        let batches = match chunk {
            SelectorChunk::Rotation(index) => {
                project(None, Some(&mut *self.nonzero));
                let row_len = layout.polynomial_length / 2;
                let factor_len = (layout.radix - 1) * row_len;
                aggregate_rotation_control_to(
                    self.nonzero,
                    &self.rotation_factors[index * factor_len..(index + 1) * factor_len],
                    self.gadget_one,
                    &mut FourierNgswCiphertext::new(
                        &mut self.rotations[index * selector_len..(index + 1) * selector_len],
                    ),
                    row_len,
                );
                return;
            }
            SelectorChunk::Table { batches, .. } => batches,
        };
        let (nlev, ngsw) = match batches {
            SelectorBatches::Unused => return,
            SelectorBatches::Nlev(_) => (Some(&mut *self.coefficients), None),
            SelectorBatches::Ngsw(_) => (
                None,
                Some(&mut self.encrypted[batches.ngsw_range(nonzero_len)]),
            ),
            SelectorBatches::Both { .. } => (
                Some(&mut *self.coefficients),
                Some(&mut self.encrypted[batches.ngsw_range(nonzero_len)]),
            ),
        };
        let fft = project(nlev, ngsw);
        if matches!(
            batches,
            SelectorBatches::Nlev(_) | SelectorBatches::Both { .. }
        ) {
            // The next chunk overwrites coefficient scratch; retain this chunk's
            // Fourier NLEVs now, at torus scale, using the original engine.
            for (coefficients, mut transformed) in
                NlevIter::new(self.coefficients, parameters.output_nlev_len()).zip(
                    FourierNlevIterMut::new(
                        &mut self.public[batches.nlev_range(full_len)],
                        selector_len,
                    ),
                )
            {
                coefficients.write_fourier_form(&mut transformed, fft);
            }
        }
    }
}
