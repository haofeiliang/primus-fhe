use primus_encoding::RoundedCodec;
use std::ops::Range;

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::{
    ngsw::{FourierNgswIter, FourierNgswIterMut},
    nlev::{FourierNlev, FourierNlevIter, FourierNlevIterMut, NlevIter},
};
use primus_ntru::{FourierNgswCiphertext, NtruCiphertext};
use primus_poly::{FourierPolynomialIter, FourierPolynomialIterMut, Polynomial};
use primus_reduce::RingContext;
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru::LweReturnEvaluator;
use primus_tfhe_ntru_fourier::{OneHotCircuitBootstrapEvaluator, ServerKey, TfheContext};

use crate::{
    HighPrecisionLookupTable, LookupTableError,
    evaluation::{check_io, copy_completed_output_to, selected_ciphertext},
    lookup_table::{
        PolynomialId, checked_allocation_len,
        selection::{OutputAction, SelectorBatches, TableNodeId, TableOperation},
    },
};

/// Native-torus Fourier high-precision lookup bound to one public table and CBS-enabled key.
///
/// Generates the surviving choices' NLEV/NGSW selectors once per evaluation.
/// Repeated subtrees share encrypted results; equal branches omit the choice.
/// Public choices lift with NLEV; encrypted choices use nonzero NGSW, including
/// chunks that require both representations. Low chunks retain aggregated
/// rotation controls. Shared results and their noise are correlated across
/// outputs; no independence of output errors is promised.
/// Public monomial factors and all online workspaces are allocated at binding.
/// Table products reuse one-hot CBS's external-product workspace between calls.
/// Outputs are converted/extracted individually, then key-switched in bounded
/// LWE tiles using the independent return evaluator; no batch of full polynomials is kept.
/// Fourier transforms also reuse its engine and the same table instance.
pub struct FourierLookupTableEvaluator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
    lookup_table: &'a HighPrecisionLookupTable<T>,
    one_hot: OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
    lwe_return: LweReturnEvaluator<'a, T, LM>,
    // [NLEV batch][branch][level][Fourier value]: full selectors for public choices.
    public_table_selectors: Box<[Complex64]>,
    // One full NLEV coefficient batch, reused when preparing each public selector batch.
    public_selector_coefficients: Box<[T]>,
    // [NGSW batch][r-1][level][Fourier value]: nonzero selectors for encrypted choices.
    encrypted_table_selectors: Box<[Complex64]>,
    // [low chunk][level][Fourier value]: one NGSW[X^(-m_i*M^i)] per low chunk.
    rotation_controls: Box<[Complex64]>,
    // One chunk's M-1 NGSW selectors for r=1..M-1, reused for each rotation control.
    nonzero_selectors: Box<[Complex64]>,
    // [low chunk i][nonzero digit k][Fourier value] of X^(-k*M^i)-1 at integer scale.
    rotation_factors: Box<[Complex64]>,
    // Trivial NGSW[1] at torus scale, with one constant g_l polynomial per row.
    gadget_one: Box<[Complex64]>,
    // [compiled scratch slot][coefficient], shared nodes survive until their last use.
    selected_tables: Box<[T]>,
    current: NtruCiphertext<Box<[T]>>,
    product: NtruCiphertext<Box<[T]>>,
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
        // The table was compiled with this q; use its own chunk encoding for one-hot CBS.
        let input_codec = RoundedCodec::new(
            lookup_table.plaintext_modulus(),
            context.parameters().external_lwe().cipher_modulus(),
        );
        let one_hot = OneHotCircuitBootstrapEvaluator::try_new(context, server_key, &input_codec)?;
        let layout = lookup_table.layout;
        let n = layout.polynomial_length;
        let coefficient_chunk_count = layout.config.coefficient_chunk_count;
        let selection = &lookup_table.selection;
        // Lengths count complex values: L*N/2 per selector, M*L*N/2 per one-hot.
        let selector_len = one_hot.ngsw_selector_len();
        let one_hot_len = one_hot.ngsw_batch_len();
        let nonzero_one_hot_len = one_hot_len - selector_len;
        let public_table_selectors_len =
            checked_allocation_len::<Complex64>(&[selection.nlev_batch_count, one_hot_len])?;
        let encrypted_table_selectors_len = checked_allocation_len::<Complex64>(&[
            selection.ngsw_batch_count,
            nonzero_one_hot_len,
        ])?;
        let selected_tables_len = checked_allocation_len::<T>(&[selection.result_slot_count, n])?;
        let rotation_controls_len =
            checked_allocation_len::<Complex64>(&[coefficient_chunk_count, selector_len])?;
        let rotation_factors_len = checked_allocation_len::<Complex64>(&[
            coefficient_chunk_count,
            layout.radix - 1,
            n / 2,
        ])?;
        let nonzero_selectors_len = if coefficient_chunk_count > 0 {
            nonzero_one_hot_len
        } else {
            0
        };
        let public_selector_coefficients_len = if selection.nlev_batch_count > 0 {
            checked_allocation_len::<T>(&[2, one_hot_len])?
        } else {
            0
        };
        let gadget_one_len = if coefficient_chunk_count > 0 {
            selector_len
        } else {
            0
        };
        let mut evaluator = Self {
            context,
            lookup_table,
            one_hot,
            lwe_return: LweReturnEvaluator::new(
                server_key.key_switching_key(),
                context.parameters().external_lwe().cipher_modulus(),
            ),
            public_table_selectors: vec![Complex64::default(); public_table_selectors_len]
                .into_boxed_slice(),
            public_selector_coefficients: vec![T::ZERO; public_selector_coefficients_len]
                .into_boxed_slice(),
            encrypted_table_selectors: vec![Complex64::default(); encrypted_table_selectors_len]
                .into_boxed_slice(),
            rotation_controls: vec![Complex64::default(); rotation_controls_len].into_boxed_slice(),
            nonzero_selectors: vec![Complex64::default(); nonzero_selectors_len].into_boxed_slice(),
            rotation_factors: vec![Complex64::default(); rotation_factors_len].into_boxed_slice(),
            gadget_one: vec![Complex64::default(); gadget_one_len].into_boxed_slice(),
            selected_tables: vec![T::ZERO; selected_tables_len].into_boxed_slice(),
            current: NtruCiphertext::zero(n),
            product: NtruCiphertext::zero(n),
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
            for (chunk_value, mut factor) in
                (1..layout.radix).zip(FourierPolynomialIterMut::new(factors, row_len))
            {
                let exponent = chunk_value * chunk_place_value;
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
    /// Each output keeps its existing coefficient buffer. All chunks are checked,
    /// including inputs skipped by the compiled plan and outputs copied from an
    /// earlier result.
    ///
    /// # Correctness
    /// Inherits one-hot CBS's key, canonical-input and quantized-phase guard
    /// requirements. Budget table products, rotations and Q-to-q/key-switch error
    /// in addition to CBS noise, native trace rounding and FFT error; parameter
    /// checks do not prove a decoding margin. Shared nodes reuse the same error,
    /// and repeated roots reuse the complete output ciphertext.
    ///
    /// # Panics
    /// Rejects wrong chunk counts or any LWE dimension before writing outputs or scratch.
    pub fn evaluate_to(&mut self, input: &[LweCiphertext<T>], output: &mut [LweCiphertext<T>]) {
        let layout = self.lookup_table.layout;
        check_io(
            layout,
            input,
            output,
            self.context.parameters().external_lwe_dimension(),
        );
        self.prepare_selectors(input);
        let capacity = self.lwe_return.batch_capacity();
        let plan = &self.lookup_table.selection;
        let mut first = 0;
        while first < output.len() {
            match plan.output_action(first) {
                OutputAction::CopyFrom(previous) => {
                    copy_completed_output_to(previous, first, output);
                    first += 1;
                }
                OutputAction::Evaluate => {
                    let tile = plan.evaluation_tile(first, capacity);
                    self.lwe_return.begin_batch();
                    self.prepare_output_returns(tile.clone());
                    first = tile.end;
                    self.lwe_return.return_batch_to(&mut output[tile]);
                }
            }
        }
    }

    /// Prepares a consecutive tile of newly evaluated outputs. Selection and
    /// rotation reuse polynomial scratch but preserve filled return slots.
    fn prepare_output_returns(&mut self, outputs: Range<usize>) {
        for output in outputs {
            self.select_table(output);
            self.rotate_selected_table();
            self.lwe_return.append_at(self.current.as_view(), 0);
        }
    }

    /// Refreshes required controls for one validated, least-significant-first input.
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
        let selector_len = self.one_hot.ngsw_selector_len();
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
                .one_hot_nonzero_ngsw_to(input.as_view(), &mut self.nonzero_selectors);
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

    /// Generates only the representations needed by surviving choices. A chunk
    /// may select both public and encrypted operands after local pruning; its
    /// NLEV and nonzero NGSW then share one BR and projection pass.
    fn prepare_table_selectors(&mut self, input: &[LweCiphertext<T>]) {
        let nonzero_len = self.one_hot.ngsw_batch_len() - self.one_hot.ngsw_selector_len();
        for (input, &batches) in input.iter().zip(&self.lookup_table.selection.selectors) {
            match batches {
                SelectorBatches::Unused => {}
                SelectorBatches::Ngsw(_) => {
                    self.one_hot.one_hot_nonzero_ngsw_to(
                        input.as_view(),
                        &mut self.encrypted_table_selectors[batches.ngsw_range(nonzero_len)],
                    );
                }
                SelectorBatches::Nlev(_) => {
                    self.one_hot
                        .one_hot_nlev_to(input.as_view(), &mut self.public_selector_coefficients);
                    self.transform_public_selectors(batches);
                }
                SelectorBatches::Both { .. } => {
                    self.one_hot.one_hot_nlev_and_nonzero_ngsw_to(
                        input.as_view(),
                        &mut self.public_selector_coefficients,
                        &mut self.encrypted_table_selectors[batches.ngsw_range(nonzero_len)],
                    );
                    self.transform_public_selectors(batches);
                }
            }
        }
    }

    /// Transforms the reusable coefficient NLEV batch into this chunk's retained
    /// Fourier batch, using the bound engine and torus scale for every gadget row.
    fn transform_public_selectors(&mut self, batches: SelectorBatches) {
        let nlev =
            &mut self.public_table_selectors[batches.nlev_range(self.one_hot.ngsw_batch_len())];
        for (coefficients, mut transformed) in NlevIter::new(
            &self.public_selector_coefficients,
            self.one_hot.parameters().output_nlev_len(),
        )
        .zip(FourierNlevIterMut::new(
            nlev,
            self.one_hot.ngsw_selector_len(),
        )) {
            coefficients.write_fourier_form(
                &mut transformed,
                self.one_hot.external_product_workspaces().0,
            );
        }
    }

    /// Rotates the selected NTRU in `current` by `X^(-z)`, where `z=sum_i m_i*M^i`.
    /// Prepared controls select the low chunks' coefficient index. Each product
    /// overwrites scratch; the final coefficient-form NTRU remains in `current`.
    fn rotate_selected_table(&mut self) {
        let basis = self.one_hot.parameters().output_basis();
        for control in
            FourierNgswIter::new(&self.rotation_controls, self.one_hot.ngsw_selector_len())
        {
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

    /// Executes this output's newly needed nodes, then copies its unrotated root.
    /// All output chunks must be consumed in order on every evaluation. Shared
    /// roots stay unmodified in their compiled slots while `current` is rotated.
    fn select_table(&mut self, output_chunk: usize) {
        let table = self.lookup_table;
        let plan = &table.selection;
        let n = table.layout.polynomial_length;
        for node in plan.scheduled_nodes(output_chunk) {
            match &node.operation {
                TableOperation::Lift(polynomial_id) => {
                    self.lift_public_polynomial(&table.polynomial_by_id(*polynomial_id))
                }
                TableOperation::SelectPublic {
                    chunk_index,
                    polynomial_ids,
                } => self.select_public_table(*chunk_index, polynomial_ids),
                TableOperation::SelectEncrypted {
                    chunk_index,
                    children,
                } => self.select_encrypted_table(*chunk_index, children),
            }
            // A destination may reuse a child's last-use slot: every operand
            // has been read into `current` before this write touches the pool.
            self.selected_tables[node.result_range(n)].copy_from_slice(self.current.as_ref());
        }
        self.current
            .as_mut()
            .copy_from_slice(&self.selected_tables[plan.root_node(output_chunk).result_range(n)]);
    }

    /// Lifts a public polynomial under f using the initializer's BR basis.
    /// Selection-tree products instead use the one-hot CBS output basis.
    fn lift_public_polynomial(&mut self, polynomial: &Polynomial<&[T]>) {
        let initializer = self.one_hot.classic_controls().initializer();
        let (fft, external_product) = self.one_hot.external_product_workspaces();
        initializer.external_product_to(
            polynomial,
            &mut self.current,
            self.context.parameters().blind_rotation().basis(),
            fft,
            external_product,
        );
    }

    /// Selects M public polynomials with full NLEV, including the default branch.
    /// Pruning can move this lift to any high chunk; the CBS output basis applies.
    fn select_public_table(&mut self, chunk_index: usize, polynomial_ids: &[PolynomialId]) {
        let table = self.lookup_table;
        let selector_batches = table.selector_batches_for_chunk(chunk_index);
        let selectors = &self.public_table_selectors
            [selector_batches.nlev_range(self.one_hot.ngsw_batch_len())];
        let basis = self.one_hot.parameters().output_basis();
        let selector_len = self.one_hot.ngsw_selector_len();
        let (fft, external_product) = self.one_hot.external_product_workspaces();
        FourierNlev::external_product_sum_to(
            FourierNlevIter::new(selectors, selector_len),
            table.polynomials(polynomial_ids),
            self.current.as_mut_view(),
            basis,
            fft,
            external_product,
        );
    }

    /// Chooses among already encrypted children using the nonzero NGSW branches.
    /// Children occupy compiled, possibly noncontiguous slots. The kernel keeps
    /// c_0 intact and performs one inverse transform after summing all products.
    fn select_encrypted_table(&mut self, chunk_index: usize, children: &[TableNodeId]) {
        let table = self.lookup_table;
        let plan = &table.selection;
        let n = table.layout.polynomial_length;
        let selector_len = self.one_hot.ngsw_selector_len();
        let nonzero_len = self.one_hot.ngsw_batch_len() - selector_len;
        let selector_batches = table.selector_batches_for_chunk(chunk_index);
        let selectors = &self.encrypted_table_selectors[selector_batches.ngsw_range(nonzero_len)];
        let ciphertext =
            |node_id| selected_ciphertext(plan.node(node_id), &self.selected_tables, n);
        let basis = self.one_hot.parameters().output_basis();
        let (fft, external_product) = self.one_hot.external_product_workspaces();
        FourierNgswCiphertext::cmux_k_to(
            FourierNgswIter::new(selectors, selector_len),
            ciphertext(children[0]),
            children[1..].iter().map(|&node_id| ciphertext(node_id)),
            self.current.as_mut_view(),
            basis,
            fft,
            external_product,
        );
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
