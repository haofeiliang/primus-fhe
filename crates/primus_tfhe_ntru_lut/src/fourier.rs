use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::{
    ngsw::{FourierNgswIter, FourierNgswIterMut},
    nlev::{FourierNlevIter, FourierNlevIterMut, NlevIter},
    ntru::{NtruIter, NtruIterMut},
};
use primus_modulus::NativeModulus;
use primus_ntru::{FourierNgswCiphertext, NtruCiphertext, NtruLweKeySwitchingWorkspace};
use primus_poly::{FourierPolynomialIter, FourierPolynomialIterMut, Polynomial, PolynomialIter};
use primus_reduce::RingContext;
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru_fourier::{OneHotCircuitBootstrapEvaluator, ServerKey, TfheContext};

use crate::{HighPrecisionLookupTable, LookupTableError, lookup_table::allocation_len};

/// Native-torus Fourier high-precision lookup bound to one public table and CBS-enabled key.
///
/// Generates each input's selectors once per evaluation and shares them across
/// all outputs. Only the first table-selection chunk retains NLEV; later table
/// chunks retain only r=1..M-1 NGSWs. Coefficient chunks retain aggregated
/// rotation controls.
/// Public monomial factors and all online workspaces are allocated at binding.
/// Table products reuse one-hot CBS's external-product workspace between calls.
/// Fourier transforms also reuse its engine and the same table instance.
pub struct FourierLookupTableEvaluator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
    server_key: &'a ServerKey<T>,
    lookup_table: &'a HighPrecisionLookupTable<T>,
    one_hot: OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
    // [branch][level][Fourier value]: M NLEVs for the first public table layer.
    public_table_selectors: Box<[Complex64]>,
    // The same first-layer NLEVs before their Fourier transform.
    public_selector_coefficients: Box<[T]>,
    // [encrypted layer][r-1][level][Fourier value]: M-1 NGSWs per later layer.
    encrypted_table_selectors: Box<[Complex64]>,
    // [low chunk][level][Fourier value]: one NGSW[X^(-m_i*M^i)] per low chunk.
    rotation_controls: Box<[Complex64]>,
    // One chunk's M-1 NGSW selectors for r=1..M-1, reused for each rotation control.
    nonzero_selectors: Box<[Complex64]>,
    // [low chunk i][nonzero digit k][Fourier value] of X^(-k*M^i)-1 at integer scale.
    rotation_factors: Box<[Complex64]>,
    // Trivial NGSW[1] at torus scale, with one constant g_l polynomial per row.
    gadget_one: Box<[Complex64]>,
    // [candidate][coefficient], holding at most P/M encrypted polynomials.
    candidates: Box<[T]>,
    current: NtruCiphertext<Box<[T]>>,
    product: NtruCiphertext<Box<[T]>>,
    difference: NtruCiphertext<Box<[T]>>,
    return_workspace: NtruLweKeySwitchingWorkspace<T>,
}

impl<'a, T, Table, LM> FourierLookupTableEvaluator<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: RingContext<T>,
{
    /// Checks table encoding, one-hot geometry and server resources, then allocates scratch.
    /// Sparse keys and keys without CBS material are rejected.
    ///
    /// # Correctness
    /// The server key must belong to this context's secrets and exact FFT table instance,
    /// as required by [`OneHotCircuitBootstrapEvaluator::try_new`].
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        server_key: &'a ServerKey<T>,
        lookup_table: &'a HighPrecisionLookupTable<T>,
    ) -> Result<Self, LookupTableError> {
        if !lookup_table.is_compatible(context.parameters()) {
            return Err(LookupTableError::IncompatibleParameters);
        }
        let one_hot = OneHotCircuitBootstrapEvaluator::try_new(context, server_key)?;
        let layout = lookup_table.layout;
        let n = layout.polynomial_length;
        let coefficient_chunk_count = layout.config.coefficient_chunk_count;
        let table_chunk_count = layout.table_chunk_count();
        // Lengths count complex values: L*N/2 per selector, M*L*N/2 per one-hot.
        let selector_len = one_hot.parameters().output_fourier_nlev_len();
        let one_hot_len = one_hot.lookup_table().output_nlev_len() / 2;
        let nonzero_one_hot_len = one_hot_len - selector_len;
        // The public layer needs all M NLEVs; encrypted layers omit default branch r=0.
        let encrypted_table_selectors_len = allocation_len::<Complex64>(&[
            table_chunk_count.saturating_sub(1),
            nonzero_one_hot_len,
        ])?;
        let rotation_controls_len =
            allocation_len::<Complex64>(&[coefficient_chunk_count, selector_len])?;
        // Public factors have no gadget levels. Candidates remain coefficient polynomials.
        let rotation_factors_len =
            allocation_len::<Complex64>(&[coefficient_chunk_count, layout.radix - 1, n / 2])?;
        let candidates_len = allocation_len::<T>(&[layout.candidate_count(), n])?;
        let mut evaluator = Self {
            context,
            server_key,
            lookup_table,
            one_hot,
            public_table_selectors: vec![
                Complex64::default();
                if table_chunk_count > 0 {
                    one_hot_len
                } else {
                    0
                }
            ]
            .into_boxed_slice(),
            public_selector_coefficients: vec![
                T::ZERO;
                if table_chunk_count > 0 {
                    2 * one_hot_len
                } else {
                    0
                }
            ]
            .into_boxed_slice(),
            encrypted_table_selectors: vec![Complex64::default(); encrypted_table_selectors_len]
                .into_boxed_slice(),
            rotation_controls: vec![Complex64::default(); rotation_controls_len].into_boxed_slice(),
            nonzero_selectors: vec![
                Complex64::default();
                if coefficient_chunk_count > 0 {
                    nonzero_one_hot_len
                } else {
                    0
                }
            ]
            .into_boxed_slice(),
            rotation_factors: vec![Complex64::default(); rotation_factors_len].into_boxed_slice(),
            gadget_one: vec![
                Complex64::default();
                if coefficient_chunk_count > 0 {
                    selector_len
                } else {
                    0
                }
            ]
            .into_boxed_slice(),
            candidates: vec![T::ZERO; candidates_len].into_boxed_slice(),
            current: NtruCiphertext::zero(n),
            product: NtruCiphertext::zero(n),
            difference: NtruCiphertext::zero(n),
            return_workspace: NtruLweKeySwitchingWorkspace::new(n),
        };
        evaluator.prepare_rotation_constants();
        Ok(evaluator)
    }

    /// Fills the preallocated public factors at integer scale and `G=NGSW[1]` at torus scale.
    /// Called once during construction, using temporary coefficient scratch.
    /// Factors follow low-chunk order, then k=1..M-1, and are shared by all outputs.
    fn prepare_rotation_constants(&mut self) {
        let layout = self.lookup_table.layout;
        let n = layout.polynomial_length;
        let row_len = n / 2;
        let mut coefficients = vec![T::ZERO; n];
        for (i, factors) in self
            .rotation_factors
            .chunks_exact_mut((layout.radix - 1) * row_len)
            .enumerate()
        {
            let chunk_place_value = 1usize << (i * layout.chunk_bits); // M^i
            for (digit, mut factor) in
                (1..layout.radix).zip(FourierPolynomialIterMut::new(factors, row_len))
            {
                let exponent = digit * chunk_place_value;
                // 0 < exponent < N, so X^(-exponent)-1 = -X^(N-exponent)-1.
                // Integer scale is required; torus scale would rescale controls.
                coefficients.fill(T::ZERO);
                coefficients[0] = T::MAX;
                coefficients[n - exponent] = T::MAX;
                self.one_hot
                    .external_product_workspaces()
                    .0
                    .forward_as_integer(&coefficients, factor.as_mut_slice());
            }
        }
        // Discard the sparse -1 coefficients of the last factor before building G.
        // Each gadget row is a constant g_l polynomial encoded at torus scale.
        coefficients.fill(T::ZERO);
        let mut gadget_one = FourierNgswCiphertext::new(self.gadget_one.as_mut());
        for (mut row, scalar) in gadget_one
            .iter_ntru_mut(row_len)
            .zip(self.one_hot.parameters().output_basis().scalar_iter())
        {
            coefficients[0] = scalar;
            self.one_hot
                .external_product_workspaces()
                .0
                .forward_as_torus(&coefficients, row.as_mut());
        }
    }

    /// Allocates the table's output chunk count at the external LWE dimension.
    #[must_use]
    pub fn allocate_output(&self) -> Vec<LweCiphertext<T>> {
        (0..self.lookup_table.config().output_chunk_count)
            .map(|_| self.context.allocate_lwe_ciphertext())
            .collect()
    }

    /// Evaluates all output chunks, overwriting caller-owned ciphertexts without allocation.
    /// Both slices are least-significant-chunk first. Inputs use `encrypt_padded`
    /// encoding; outputs are decoded with the same context's ordinary decryptor.
    ///
    /// # Correctness
    /// Inherits one-hot CBS's key, canonical-input and quantized-phase guard
    /// requirements. Budget table products, rotations and Q-to-q/key-switch error
    /// in addition to CBS noise, native trace rounding and FFT error; parameter
    /// checks do not prove a decoding margin.
    ///
    /// # Panics
    /// Rejects wrong chunk counts or any LWE dimension before writing outputs or scratch.
    pub fn evaluate_to(&mut self, input: &[LweCiphertext<T>], output: &mut [LweCiphertext<T>]) {
        let layout = self.lookup_table.layout;
        layout.check_io(
            input,
            output,
            self.context.parameters().external_lwe_dimension(),
        );
        self.prepare_selectors(input);
        for (index, output) in output.iter_mut().enumerate() {
            self.select_table(index);
            self.rotate_selected_table();
            self.server_key.key_switching_key().key_switch_to(
                &self.current,
                output,
                self.context.parameters().external_lwe().cipher_modulus(),
                &mut self.return_workspace,
            );
        }
    }

    /// Refreshes all controls for one validated, least-significant-first input.
    /// Low chunks produce rotation controls; high chunks produce table selectors.
    /// These buffers are prepared once and reused for every output chunk.
    fn prepare_selectors(&mut self, input: &[LweCiphertext<T>]) {
        let (coefficient_chunks, table_chunks) =
            input.split_at(self.lookup_table.config().coefficient_chunk_count);
        self.prepare_rotation_controls(coefficient_chunks);
        self.prepare_table_selectors(table_chunks);
    }

    /// Overwrites one `NGSW[X^(-m_i*M^i)]` control per low input chunk.
    /// Input contains exactly d chunks, matching the control and factor batches
    /// allocated at construction. One nonzero-selector scratch batch is reused.
    fn prepare_rotation_controls(&mut self, input: &[LweCiphertext<T>]) {
        let layout = self.lookup_table.layout;
        let row_len = layout.polynomial_length / 2;
        let selector_len = self.one_hot.parameters().output_fourier_nlev_len();
        let factors_chunk_len = (layout.radix - 1) * row_len;
        // All three batches follow low-chunk order: input m_i, output C_i,
        // and the M-1 public factors X^(-k*M^i)-1 for this same i.
        for ((input, mut control), factors) in input
            .iter()
            .zip(FourierNgswIterMut::new(
                &mut self.rotation_controls,
                selector_len,
            ))
            .zip(self.rotation_factors.chunks_exact(factors_chunk_len))
        {
            self.one_hot
                .one_hot_nonzero_ngsw_to(input, &mut self.nonzero_selectors);
            // Save this chunk's aggregated rotation control.
            // The next chunk overwrites `nonzero_selectors` with its own M-1 selectors.
            aggregate_rotation_control_to(
                &self.nonzero_selectors,
                factors,
                &self.gadget_one,
                &mut control,
                row_len,
            );
        }
    }

    /// Prepares selectors for the high chunks, starting with input chunk d.
    /// The first chunk uses all M NLEVs to select and lift public polynomials;
    /// remaining chunks need only r=1..M-1 NGSWs because c_0 supplies the default
    /// branch. Empty input means d=c.
    fn prepare_table_selectors(&mut self, input: &[LweCiphertext<T>]) {
        let Some((first, remaining)) = input.split_first() else {
            return;
        };
        let selector_len = self.one_hot.parameters().output_fourier_nlev_len();
        let nonzero_one_hot_len = (self.lookup_table.layout.radix - 1) * selector_len;
        self.one_hot
            .one_hot_nlev_to(first, &mut self.public_selector_coefficients);
        // Transform every coefficient-form gadget row in the M-selector batch
        // with the bound FFT table, preserving the ciphertext's torus scale.
        for (coefficients, mut transformed) in NlevIter::new(
            &self.public_selector_coefficients,
            self.one_hot.parameters().output_nlev_len(),
        )
        .zip(FourierNlevIterMut::new(
            &mut self.public_table_selectors,
            selector_len,
        )) {
            coefficients.write_fourier_form(
                &mut transformed,
                self.one_hot.external_product_workspaces().0,
            );
        }
        for (input, selectors) in remaining.iter().zip(
            self.encrypted_table_selectors
                .chunks_exact_mut(nonzero_one_hot_len),
        ) {
            self.one_hot.one_hot_nonzero_ngsw_to(input, selectors);
        }
    }

    /// Rotates the selected NTRU in `current` by `X^(-z)`, where `z=sum_i m_i*M^i`.
    /// Prepared controls select the low chunks' coefficient index. Each product
    /// overwrites scratch; the final coefficient-form NTRU remains in `current`.
    fn rotate_selected_table(&mut self) {
        let basis = self.one_hot.parameters().output_basis();
        for control in FourierNgswIter::new(
            &self.rotation_controls,
            self.one_hot.parameters().output_fourier_nlev_len(),
        ) {
            let (fft, external_product) = self.one_hot.external_product_workspaces();
            control.external_product_to(
                &self.current,
                &mut self.product,
                basis,
                fft,
                external_product,
            );
            // Keep the new accumulator in `current` for both odd and even
            // rotation counts, without copying its N coefficients.
            core::mem::swap(&mut self.current, &mut self.product);
        }
    }

    /// Overwrites `current` with the selected LUT polynomial encrypted under f.
    /// Selectors must already correspond to the input, and `output_chunk` must
    /// index a configured output. Candidate storage is reused across outputs;
    /// coefficient selection is performed separately by `rotate_selected_table`.
    fn select_table(&mut self, output_chunk: usize) {
        let layout = self.lookup_table.layout;
        let n = layout.polynomial_length;
        let table_chunk_count = layout.table_chunk_count();
        let coefficients_per_output = layout.polynomials_per_output * n;
        let polynomials = &self.lookup_table.coefficients
            [output_chunk * coefficients_per_output..(output_chunk + 1) * coefficients_per_output];
        if table_chunk_count == 0 {
            // No table-selection chunks: c=d, so M^(c-d)=1 and this slice
            // contains exactly one polynomial of length n.
            debug_assert_eq!(polynomials.len(), n);
            // A public coefficient array is not an NTRU encryption under f.
            // Even without a selection tree, lift it using the initializer's BR basis.
            let (fft, external_product) = self.one_hot.external_product_workspaces();
            self.server_key.initializer().external_product_to(
                &Polynomial::new(polynomials),
                &mut self.current,
                self.context.parameters().blind_rotation().basis(),
                fft,
                external_product,
            );
            return;
        }
        self.select_public_table_groups(polynomials);
        let mut candidate_count = layout.candidate_count();
        // The public layer consumed chunk d. Each remaining layer consumes
        // the next higher chunk and reduces the live candidate count by M.
        for layer in 0..table_chunk_count - 1 {
            candidate_count = self.select_encrypted_table_layer(layer, candidate_count);
        }
        debug_assert_eq!(candidate_count, 1);
        self.current.as_mut().copy_from_slice(&self.candidates[..n]);
    }

    /// Evaluates the public first layer: `sum_k T_k odot NLEV[delta_k]`.
    /// Input holds all P*N coefficients for one output, with P>=M. Each adjacent
    /// M-polynomial group writes one NTRU to `candidates`, overwriting all P/M
    /// candidate slots. The default branch also participates in the lifting.
    fn select_public_table_groups(&mut self, polynomials: &[T]) {
        let layout = self.lookup_table.layout;
        let n = layout.polynomial_length;
        let modulus = NativeModulus::<T>::new();
        let basis = self.one_hot.parameters().output_basis();
        let selector_len = self.one_hot.parameters().output_fourier_nlev_len();
        // Consecutive polynomials vary in the lowest unresolved table chunk;
        // each group fixes all higher chunks and shares this layer's selectors.
        for (group, mut candidate) in polynomials
            .chunks_exact(layout.radix * n)
            .zip(NtruIterMut::new(&mut self.candidates, n))
        {
            for (k, (polynomial, selector)) in PolynomialIter::new(group, n)
                .zip(FourierNlevIter::new(
                    &self.public_table_selectors,
                    selector_len,
                ))
                .enumerate()
            {
                let (fft, external_product) = self.one_hot.external_product_workspaces();
                selector.external_product_to(
                    &polynomial,
                    &mut self.product,
                    basis,
                    fft,
                    external_product,
                );
                // Initialize from the first product so reused candidate slots
                // need no clearing and cannot retain a previous output's sum.
                if k == 0 {
                    candidate.as_mut().copy_from_slice(self.product.as_ref());
                } else {
                    candidate.add_assign(&self.product, modulus);
                }
            }
        }
    }

    /// Reduces an encrypted layer by `c_0 + sum_{k>0}(c_k-c_0) otimes NGSW[delta_k]`.
    /// `layer` indexes only encrypted layers: zero uses input chunk d+1.
    /// On entry, `input_candidate_count` live NTRUs occupy the candidate prefix,
    /// and their count is divisible by M. Results overwrite that prefix; the
    /// returned count is the number of live NTRUs for the next layer.
    fn select_encrypted_table_layer(
        &mut self,
        layer: usize,
        input_candidate_count: usize,
    ) -> usize {
        let layout = self.lookup_table.layout;
        let n = layout.polynomial_length;
        let modulus = NativeModulus::<T>::new();
        let basis = self.one_hot.parameters().output_basis();
        let selector_len = self.one_hot.parameters().output_fourier_nlev_len();
        let nonzero_one_hot_len = (layout.radix - 1) * selector_len;
        let selectors = &self.encrypted_table_selectors
            [layer * nonzero_one_hot_len..(layer + 1) * nonzero_one_hot_len];
        let group_len = layout.radix * n;
        let output_candidate_count = input_candidate_count / layout.radix;
        for output_index in 0..output_candidate_count {
            let group_start = output_index * group_len;
            let group = &self.candidates[group_start..group_start + group_len];
            let (default, alternatives) = group.split_at(n);
            let default = NtruCiphertext::new(default);
            // The default ciphertext supplies k=0 directly. Every difference
            // must use this unchanged c_0, not the accumulating `current`.
            self.current.as_mut().copy_from_slice(default.as_ref());
            for (candidate, selector) in
                NtruIter::new(alternatives, n).zip(FourierNgswIter::new(selectors, selector_len))
            {
                candidate.sub_to(&default, &mut self.difference, modulus);
                let (fft, external_product) = self.one_hot.external_product_workspaces();
                selector.external_product_to(
                    &self.difference,
                    &mut self.product,
                    basis,
                    fft,
                    external_product,
                );
                self.current.add_assign(&self.product, modulus);
            }
            // Read the entire group before compacting its result. The destination
            // is within the consumed prefix, before every unread input group.
            self.candidates[output_index * n..(output_index + 1) * n]
                .copy_from_slice(self.current.as_ref());
        }
        output_candidate_count
    }
}

/// Overwrites one Fourier control with `C_i=G+sum_{k>0}(X^(-k*M^i)-1)*NGSW[delta_k(m_i)]`.
/// With R=row_len=N/2, `selectors` holds (M-1)*L*R values for r=1..M-1 and
/// `factors` holds (M-1)*R; `gadget_one` and `output` each hold L*R.
/// All arrays use the same FFT table. G and selectors share gadget row order
/// and torus scale, while factors use integer scale. The target plaintext is
/// `X^(-m_i*M^i)`, including the default m_i=0.
fn aggregate_rotation_control_to(
    selectors: &[Complex64],
    factors: &[Complex64],
    gadget_one: &[Complex64],
    output: &mut FourierNgswCiphertext<&mut [Complex64]>,
    row_len: usize,
) {
    let selector_len = gadget_one.len();
    output.as_mut().copy_from_slice(gadget_one);
    // Both iterators start at branch one. G supplies the default monomial 1;
    // each public factor multiplies all gadget rows of its selector.
    for (selector, factor) in FourierNgswIter::new(selectors, selector_len)
        .zip(FourierPolynomialIter::new(factors, row_len))
    {
        output.add_mul_fourier_polynomial_assign(&selector, &factor);
    }
}
