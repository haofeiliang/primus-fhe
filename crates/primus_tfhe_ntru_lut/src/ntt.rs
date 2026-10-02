use primus_integer::FheUint;
use primus_lattice::{
    ngsw::{NttNgswIter, NttNgswIterMut},
    nlev::{NttNlev, NttNlevIter},
};
use primus_modulus::BarrettModulus;
use primus_ntru::{NtruCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomialIter, NttPolynomialIterMut, Polynomial, PolynomialIterMut};
use primus_reduce::{ReduceSub, RingContext};
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru::{CircuitBootstrapParameters, LweReturnEvaluator};
use primus_tfhe_ntru_ntt::{OneHotCircuitBootstrapEvaluator, ServerKey, TfheContext};

use crate::{
    HighPrecisionLookupTable, LookupTableError,
    evaluation::{check_io, copy_completed_output_to, selected_ciphertext},
    lookup_table::{
        PolynomialId, checked_allocation_len,
        selection::{OutputAction, SelectorBatches, TableNodeId, TableOperation},
    },
};

/// Exact-NTT high-precision lookup bound to one public table and CBS-enabled key.
///
/// Generates the surviving choices' NLEV/NGSW selectors once per evaluation.
/// Repeated subtrees share encrypted results; equal branches omit the choice.
/// Public choices lift with NLEV; encrypted choices use nonzero NGSW, including
/// chunks that require both representations. Low chunks retain aggregated
/// rotation controls. Shared results and their noise are correlated across
/// outputs; no independence of output errors is promised.
/// Public monomial factors and all online workspaces are allocated at binding.
/// Table products reuse one-hot CBS's external-product workspace between calls.
pub struct NttLookupTableEvaluator<'a, T, Table, LM = BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
    lookup_table: &'a HighPrecisionLookupTable<T>,
    one_hot: OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
    lwe_return: LweReturnEvaluator<'a, T, LM>,
    // [NLEV batch][branch][level][NTT value]: full selectors for public choices.
    public_table_selectors: Box<[T]>,
    // [NGSW batch][r-1][level][NTT value]: nonzero selectors for encrypted choices.
    encrypted_table_selectors: Box<[T]>,
    // [low chunk][level][NTT value]: one NGSW[X^(-m_i*M^i)] per low chunk.
    rotation_controls: Box<[T]>,
    // One chunk's M-1 NGSW selectors for r=1..M-1, reused for each rotation control.
    nonzero_selectors: Box<[T]>,
    // [low chunk i][nonzero digit k][NTT value] of X^(-k*M^i)-1.
    rotation_factors: Box<[T]>,
    // [compiled scratch slot][coefficient], shared nodes survive until their last use.
    selected_tables: Box<[T]>,
    current: NtruCiphertext<Box<[T]>>,
    product: NtruCiphertext<Box<[T]>>,
}

impl<'a, T, Table, LM> NttLookupTableEvaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: RingContext<T>,
{
    /// Checks table encoding, one-hot geometry and server resources, then allocates scratch.
    /// Sparse keys and keys without CBS material are rejected.
    ///
    /// # Correctness
    /// The server key must belong to this context's secrets and NTT representation,
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
        let selection = &lookup_table.selection;
        // Lengths count T values: one selector has L*N, one-hot has M*L*N.
        let selector_len = one_hot.ngsw_selector_len();
        let one_hot_len = one_hot.ngsw_batch_len();
        let nonzero_one_hot_len = one_hot_len - selector_len;
        let public_table_selectors_len =
            checked_allocation_len::<T>(&[selection.nlev_batch_count, one_hot_len])?;
        let encrypted_table_selectors_len =
            checked_allocation_len::<T>(&[selection.ngsw_batch_count, nonzero_one_hot_len])?;
        let selected_tables_len = checked_allocation_len::<T>(&[selection.result_slot_count, n])?;
        let rotation_controls_len =
            checked_allocation_len::<T>(&[coefficient_chunk_count, selector_len])?;
        let rotation_factors_len =
            checked_allocation_len::<T>(&[coefficient_chunk_count, layout.radix - 1, n])?;
        let nonzero_selectors_len = if coefficient_chunk_count > 0 {
            nonzero_one_hot_len
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
            public_table_selectors: vec![T::ZERO; public_table_selectors_len].into_boxed_slice(),
            encrypted_table_selectors: vec![T::ZERO; encrypted_table_selectors_len]
                .into_boxed_slice(),
            rotation_controls: vec![T::ZERO; rotation_controls_len].into_boxed_slice(),
            nonzero_selectors: vec![T::ZERO; nonzero_selectors_len].into_boxed_slice(),
            rotation_factors: vec![T::ZERO; rotation_factors_len].into_boxed_slice(),
            selected_tables: vec![T::ZERO; selected_tables_len].into_boxed_slice(),
            current: NtruCiphertext::zero(n),
            product: NtruCiphertext::zero(n),
        };
        evaluator.prepare_rotation_constants();
        Ok(evaluator)
    }

    /// Fills the preallocated NTT factors X^(-k*M^i)-1, k=1..M-1, for each low chunk.
    /// Called once during construction; factor order matches the nonzero selectors
    /// in `aggregate_rotation_control_to`, and the factors are shared by all outputs.
    fn prepare_rotation_constants(&mut self) {
        let layout = self.lookup_table.layout;
        let n = layout.polynomial_length;
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        for (i, factors) in self
            .rotation_factors
            .chunks_exact_mut((layout.radix - 1) * n)
            .enumerate()
        {
            let chunk_place_value = 1usize << (i * layout.chunk_bits); // M^i
            for (chunk_value, mut factor) in
                (1..layout.radix).zip(NttPolynomialIterMut::new(factors, n))
            {
                let exponent = chunk_value * chunk_place_value;
                // M^d<=N gives 0<exponent<N. Negacyclic monomials have period 2N,
                // so 2N-exponent represents the required negative rotation.
                self.context
                    .table()
                    .transform_coeff_one_monomial(2 * n - exponent, factor.as_mut_slice());
                // NTT(1) is one at every evaluation point, not just the first entry.
                for value in factor.iter_mut() {
                    *value = modulus.reduce_sub(*value, T::ONE);
                }
            }
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
    /// in addition to CBS noise; parameter checks do not prove a decoding margin.
    /// Pruning changes products and error correlations. Shared subtrees reuse
    /// the same ciphertext, including its error, across their consumers.
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
        for index in 0..output.len() {
            match self.lookup_table.selection.output_action(index) {
                OutputAction::CopyFrom(previous) => {
                    copy_completed_output_to(previous, index, output)
                }
                OutputAction::Evaluate => {
                    self.select_table(index);
                    self.rotate_selected_table();
                    self.lwe_return
                        .return_at_to(self.current.as_view(), 0, &mut output[index]);
                }
            }
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
        let selector_len = self.one_hot.ngsw_selector_len();
        let factors_chunk_len = (layout.radix - 1) * layout.polynomial_length;
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        // All three batches follow low-chunk order: input m_i, output C_i,
        // and the M-1 public factors X^(-k*M^i)-1 for this same i.
        for ((input, mut control), factors) in input
            .iter()
            .zip(NttNgswIterMut::new(
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
                &mut control,
                self.one_hot.parameters(),
                modulus,
            );
        }
    }

    /// Generates only the representations needed by surviving choices. A chunk
    /// may select both public and encrypted operands after local pruning; its
    /// NLEV and nonzero NGSW then share one BR and projection pass.
    fn prepare_table_selectors(&mut self, input: &[LweCiphertext<T>]) {
        let full_len = self.one_hot.ngsw_batch_len();
        let nonzero_len = full_len - self.one_hot.ngsw_selector_len();
        for (input, &batches) in input.iter().zip(&self.lookup_table.selection.selectors) {
            match batches {
                SelectorBatches::Unused => {}
                SelectorBatches::Ngsw(_) => {
                    self.one_hot.one_hot_nonzero_ngsw_to(
                        input,
                        &mut self.encrypted_table_selectors[batches.ngsw_range(nonzero_len)],
                    );
                }
                SelectorBatches::Nlev(_) => {
                    self.one_hot.one_hot_nlev_to(
                        input,
                        &mut self.public_table_selectors[batches.nlev_range(full_len)],
                    );
                    self.transform_public_selectors(batches);
                }
                SelectorBatches::Both { .. } => {
                    self.one_hot.one_hot_nlev_and_nonzero_ngsw_to(
                        input,
                        &mut self.public_table_selectors[batches.nlev_range(full_len)],
                        &mut self.encrypted_table_selectors[batches.ngsw_range(nonzero_len)],
                    );
                    self.transform_public_selectors(batches);
                }
            }
        }
    }

    /// NLEV projection writes coefficients; public products consume NTT rows.
    /// Both request forms transform the same full batch exactly once.
    fn transform_public_selectors(&mut self, batches: SelectorBatches) {
        let nlev =
            &mut self.public_table_selectors[batches.nlev_range(self.one_hot.ngsw_batch_len())];
        for row in PolynomialIterMut::new(nlev, self.lookup_table.layout.polynomial_length) {
            self.context.table().transform_slice(row.0);
        }
    }

    /// Rotates the selected NTRU in `current` by `X^(-z)`, where `z=sum_i m_i*M^i`.
    /// Prepared controls select the low chunks' coefficient index. Each product
    /// overwrites scratch; the final coefficient-form NTRU remains in `current`.
    fn rotate_selected_table(&mut self) {
        let basis = self.one_hot.parameters().output_basis();
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();

        for control in NttNgswIter::new(&self.rotation_controls, self.one_hot.ngsw_selector_len()) {
            control.external_product_to(
                &self.current,
                &mut self.product,
                basis,
                modulus,
                self.context.table(),
                self.one_hot.external_product_workspace(),
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
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        self.one_hot
            .classic_controls()
            .initializer()
            .external_product_to(
                polynomial,
                &mut self.current,
                self.context.parameters().blind_rotation().basis(),
                modulus,
                self.context.table(),
                self.one_hot.external_product_workspace(),
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
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        NttNlev::external_product_sum_to(
            NttNlevIter::new(selectors, selector_len),
            table.polynomials(polynomial_ids),
            self.current.as_mut_view(),
            basis,
            modulus,
            self.context.table(),
            self.one_hot.external_product_workspace(),
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
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        NttNgswCiphertext::cmux_k_to(
            NttNgswIter::new(selectors, selector_len),
            ciphertext(children[0]),
            children[1..].iter().map(|&node_id| ciphertext(node_id)),
            self.current.as_mut_view(),
            basis,
            modulus,
            self.context.table(),
            self.one_hot.external_product_workspace(),
        );
    }
}

/// Overwrites one NTT control with `C_i=G+sum_{k>0}(X^(-k*M^i)-1)*NGSW[delta_k(m_i)]`.
/// `selectors` holds (M-1)*L*N values for r=1..M-1, `factors` holds (M-1)*N,
/// and `output` holds L*N. All inputs use canonical residues in the same NTT
/// representation and modulus; selector rows use the supplied CBS basis.
/// The target plaintext is `X^(-m_i*M^i)`; for m_i=0, all selector target bits are zero.
fn aggregate_rotation_control_to<T: FheUint>(
    selectors: &[T],
    factors: &[T],
    output: &mut NttNgswCiphertext<&mut [T]>,
    parameters: &CircuitBootstrapParameters<T, BarrettModulus<T>>,
    modulus: BarrettModulus<T>,
) {
    let n = parameters.poly_length().get();
    let selector_len = parameters.output_nlev_len();
    // Constant polynomial g_l transforms to the constant NTT row g_l.
    for (mut row, scalar) in output
        .iter_ntt_ntru_mut(n)
        .zip(parameters.output_basis().scalar_iter())
    {
        row.as_mut().fill(scalar);
    }
    // Both iterators start at branch one. G supplies the default monomial 1;
    // each public factor multiplies all gadget rows of its selector.
    for (selector, factor) in
        NttNgswIter::new(selectors, selector_len).zip(NttPolynomialIter::new(factors, n))
    {
        output.add_mul_ntt_polynomial_assign(&selector, &factor, modulus);
    }
}
