use primus_integer::FheUint;
use primus_lattice::{
    ngsw::{NttNgswIter, NttNgswIterMut},
    nlev::NttNlevIter,
    ntru::{NtruIter, NtruIterMut},
};
use primus_modulus::BarrettModulus;
use primus_ntru::{
    NtruCiphertext, NtruLweKeySwitchingContext, NttNgswCiphertext, NttNtruExternalProductContext,
};
use primus_ntt::MonomialNttTable;
use primus_poly::{
    NttPolynomialIter, NttPolynomialIterMut, Polynomial, PolynomialIter, PolynomialIterMut,
};
use primus_reduce::{ReduceSub, RingContext};
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru::CircuitBootstrapParameters;
use primus_tfhe_ntru_ntt::{OneHotCircuitBootstrapEvaluator, ServerKey, TfheContext};

use crate::{HighPrecisionLookupTable, LookupTableError, lookup_table::allocation_len};

/// Exact-NTT high-precision lookup bound to one public table and CBS-enabled key.
///
/// Generates each input's selectors once per evaluation and shares them across
/// all outputs. Only the first table-selection chunk retains NLEV; later table
/// chunks retain only r=1..M-1 NGSWs. Coefficient chunks retain aggregated
/// rotation controls.
/// Public monomial factors and all online workspaces are allocated at binding.
pub struct NttLookupTableEvaluator<'a, T, Table, LM = BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
    server_key: &'a ServerKey<T>,
    lookup_table: &'a HighPrecisionLookupTable<T>,
    one_hot: OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
    // [branch][level][NTT value]: M NLEVs for the first public table layer.
    public_table_selectors: Vec<T>,
    // [encrypted layer][r-1][level][NTT value]: M-1 NGSWs per later layer.
    encrypted_table_selectors: Vec<T>,
    // [low chunk][level][NTT value]: one NGSW[X^(-m_i*M^i)] per low chunk.
    rotation_controls: Vec<T>,
    // One chunk's M-1 NGSW selectors for r=1..M-1, reused for each rotation control.
    nonzero_selectors: Vec<T>,
    // [low chunk i][nonzero digit k][NTT value] of X^(-k*M^i)-1.
    rotation_factors: Vec<T>,
    // [candidate][coefficient], holding at most P/M encrypted polynomials.
    candidates: Vec<T>,
    current: NtruCiphertext<Vec<T>>,
    product: NtruCiphertext<Vec<T>>,
    difference: NtruCiphertext<Vec<T>>,
    external_product: NttNtruExternalProductContext<T>,
    return_context: NtruLweKeySwitchingContext<T>,
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
        let table_chunk_count = layout.table_chunk_count();
        // Lengths count T values: one selector has L*N, one-hot has M*L*N.
        let selector_len = one_hot.parameters().output_nlev_len();
        let one_hot_len = one_hot.lookup_table().output_nlev_len();
        let nonzero_one_hot_len = one_hot_len - selector_len;
        // The public layer needs all M NLEVs; encrypted layers omit default branch r=0.
        let encrypted_table_selectors_len =
            allocation_len::<T>(&[table_chunk_count.saturating_sub(1), nonzero_one_hot_len])?;
        let rotation_controls_len = allocation_len::<T>(&[coefficient_chunk_count, selector_len])?;
        // Public factors have no gadget levels. Candidates remain coefficient polynomials.
        let rotation_factors_len =
            allocation_len::<T>(&[coefficient_chunk_count, layout.radix - 1, n])?;
        let candidates_len = allocation_len::<T>(&[layout.candidate_count(), n])?;
        let mut evaluator = Self {
            context,
            server_key,
            lookup_table,
            one_hot,
            public_table_selectors: vec![
                T::ZERO;
                if table_chunk_count > 0 {
                    one_hot_len
                } else {
                    0
                }
            ],
            encrypted_table_selectors: vec![T::ZERO; encrypted_table_selectors_len],
            rotation_controls: vec![T::ZERO; rotation_controls_len],
            nonzero_selectors: vec![
                T::ZERO;
                if coefficient_chunk_count > 0 {
                    nonzero_one_hot_len
                } else {
                    0
                }
            ],
            rotation_factors: vec![T::ZERO; rotation_factors_len],
            candidates: vec![T::ZERO; candidates_len],
            current: NtruCiphertext::zero(n),
            product: NtruCiphertext::zero(n),
            difference: NtruCiphertext::zero(n),
            external_product: NttNtruExternalProductContext::new(n),
            return_context: NtruLweKeySwitchingContext::new(n),
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
            for (digit, mut factor) in (1..layout.radix).zip(NttPolynomialIterMut::new(factors, n))
            {
                let exponent = digit * chunk_place_value;
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
                &mut self.return_context,
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
        let selector_len = self.one_hot.parameters().output_nlev_len();
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

    /// Prepares selectors for the high chunks, starting with input chunk d.
    /// The first chunk uses all M NLEVs to select and lift public polynomials;
    /// remaining chunks need only r=1..M-1 NGSWs because c_0 supplies the default
    /// branch. Empty input means d=c.
    fn prepare_table_selectors(&mut self, input: &[LweCiphertext<T>]) {
        let Some((first, remaining)) = input.split_first() else {
            return;
        };
        let n = self.lookup_table.layout.polynomial_length;
        let selector_len = self.one_hot.parameters().output_nlev_len();
        let nonzero_one_hot_len = (self.lookup_table.layout.radix - 1) * selector_len;

        // one_hot_nlev_to returns coefficient-form rows; public-polynomial
        // external products require each row in this context's NTT representation.
        self.one_hot
            .one_hot_nlev_to(first, &mut self.public_table_selectors);
        for mut row in PolynomialIterMut::new(&mut self.public_table_selectors, n) {
            self.context.table().transform_slice(row.as_mut_slice());
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
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();

        for control in NttNgswIter::new(
            &self.rotation_controls,
            self.one_hot.parameters().output_nlev_len(),
        ) {
            control.external_product_to(
                &self.current,
                &mut self.product,
                basis,
                modulus,
                self.context.table(),
                &mut self.external_product,
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
            let modulus = self
                .context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus();
            self.server_key.initializer().external_product_to(
                &Polynomial::new(polynomials),
                &mut self.current,
                self.context.parameters().blind_rotation().basis(),
                modulus,
                self.context.table(),
                &mut self.external_product,
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
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        let basis = self.one_hot.parameters().output_basis();
        let selector_len = self.one_hot.parameters().output_nlev_len();

        // Consecutive polynomials vary in the lowest unresolved table chunk;
        // each group fixes all higher chunks and shares this layer's selectors.
        for (group, mut candidate) in polynomials
            .chunks_exact(layout.radix * n)
            .zip(NtruIterMut::new(&mut self.candidates, n))
        {
            for (k, (polynomial, selector)) in PolynomialIter::new(group, n)
                .zip(NttNlevIter::new(&self.public_table_selectors, selector_len))
                .enumerate()
            {
                selector.external_product_to(
                    &polynomial,
                    &mut self.product,
                    basis,
                    modulus,
                    self.context.table(),
                    &mut self.external_product,
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
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        let basis = self.one_hot.parameters().output_basis();
        let selector_len = self.one_hot.parameters().output_nlev_len();
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
                NtruIter::new(alternatives, n).zip(NttNgswIter::new(selectors, selector_len))
            {
                candidate.sub_to(&default, &mut self.difference, modulus);
                selector.external_product_to(
                    &self.difference,
                    &mut self.product,
                    basis,
                    modulus,
                    self.context.table(),
                    &mut self.external_product,
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
    let n = parameters.poly_length();
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
