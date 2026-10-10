//! Selector destinations and constants borrowed independently of one-hot CBS.

use primus_fft::{Complex64, FftEngine, FftTable, TorusFftValue};
use primus_lattice::nlev::{FourierNlevIterMut, NlevIter};
use primus_modulus::NativeModulus;
use primus_ntru::FourierNgswCiphertext;
use primus_tfhe_ntru::CbsGadgetParameters;

use super::aggregate_rotation_control_to;
use crate::{evaluation::SelectorOutput, lookup_table::Layout};

/// Borrowed destinations and immutable rotation constants. Projection and its
/// consumer finish before the next input reuses the coefficient/nonzero scratch.
/// Allocation lengths follow the fixed roles of the low and high input chunks.
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
    /// Low chunks retain only their aggregated monomial controls. The first high
    /// chunk retains all M NLEVs; later high chunks retain M-1 NGSWs each.
    /// The callback performs a serial BR or consumes one prepared pair member,
    /// then lends its FFT engine for the coefficient NLEV conversion.
    pub fn project_chunk<'f, 'a: 'f, Table: FftTable + 'a>(
        &mut self,
        index: usize,
        layout: Layout,
        parameters: &CbsGadgetParameters<T, NativeModulus<T>>,
        project: impl FnOnce(SelectorOutput<'_, T, Complex64>) -> &'f mut FftEngine<'a, Table>,
    ) {
        let selector_len = parameters.output_nlev_len() / 2;
        let d = layout.config.coefficient_chunk_count;
        if index < d {
            project(SelectorOutput::Ngsw(self.nonzero));
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
        } else if index == d {
            let fft = project(SelectorOutput::Nlev(self.coefficients));
            // Keep torus-scaled Fourier rows for every first-layer public group.
            // Use the projection's own engine/table for this one conversion pass.
            for (coefficients, mut transformed) in
                NlevIter::new(self.coefficients, parameters.output_nlev_len())
                    .zip(FourierNlevIterMut::new(self.public, selector_len))
            {
                coefficients.write_fourier_form(&mut transformed, fft);
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
