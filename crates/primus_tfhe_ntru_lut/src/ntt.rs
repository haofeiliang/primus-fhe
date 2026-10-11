use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_lattice::{
    ngsw::NttNgswIter,
    nlev::{NttNlev, NttNlevIter},
    ntru::NtruIter,
};
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;
use primus_poly::{NttPolynomialIter, NttPolynomialIterMut, Polynomial, PolynomialIter};
use primus_reduce::{ReduceSub, RingContext};
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru::{CbsGadgetParameters, LweReturnEvaluator};
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapServerKey, TfheContext,
    circuit_bootstrap::{CircuitBootstrapKey, OneHotCircuitBootstrapEvaluator},
    key::BlindRotationKey,
};
use selectors::SelectorBuffers;

use crate::{
    HighPrecisionLookupTable, LookupTableError,
    evaluation::{SelectorOutput, check_io},
};

mod context;
mod selectors;
pub use context::{
    NttHighPrecLutContext, NttHighPrecLutContextError, NttHighPrecLutServerKey, NttPublicLiftKey,
};

/// Borrowed `NLEV[1]` view and its generation parameters for public polynomial lifting.
/// This tuple owns no buffers and performs no validation; binding through
/// [`NttLookupTableEvaluator::try_from_parts`] checks the ring and storage layout.
/// The caller guarantees the encoded one, actual secret, basis and transform identity.
pub type NttPublicLift<'a, T> = (NttNlev<&'a [T]>, &'a NlevParameters<T, BarrettModulus<T>>);

/// Exact-NTT high-precision lookup bound to one public table and CBS-enabled key.
///
/// Generates one batch of selectors per input chunk, shared by all outputs.
/// Every output executes the complete selection tree: full NLEV at its first
/// layer, then nonzero NGSW for each later layer. Repeated tables do not skip work.
/// Low chunks retain aggregated rotation controls; shared selectors and controls
/// can correlate output errors. Sparse BR prepares input chunks in pairs, with
/// one extra input state only when at least two chunks need BR.
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
    resources: primus_tfhe_ntru_ntt::bootstrap::BootstrapResources<'a, T, Table, LM>,
    one_hot: OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
    // One extra input state; transform, product and projection scratch stay shared.
    sparse_pair: Option<primus_tfhe_ntru_ntt::sparse::SparseBlindRotationPairWorkspace<T>>,
    // Present only for c=d (no selection layer), with its own basis.
    public_lift: Option<NttPublicLift<'a, T>>,
    lwe_return: LweReturnEvaluator<'a, T, LM>,
    scalar_return: primus_ntru::NtruLweKeySwitchingWorkspace<T>,
    // [branch][level][NTT value]: full selectors for public choices.
    public_table_selectors: Box<[T]>,
    // [high chunk after the first][r-1][level][NTT value]: nonzero selectors for encrypted choices.
    encrypted_table_selectors: Box<[T]>,
    // [low chunk][level][NTT value]: one NGSW[X^(-m_i*M^i)] per low chunk.
    rotation_controls: Box<[T]>,
    // One chunk's M-1 NGSW selectors for r=1..M-1, reused for each rotation control.
    nonzero_selectors: Box<[T]>,
    // [low chunk i][nonzero digit k][NTT value] of X^(-k*M^i)-1.
    rotation_factors: Box<[T]>,
    // [encrypted layer][branch][coefficient]: M children, reused after their parent.
    // Only M*(h-1) NTRUs are retained, not the complete intermediate tree.
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
    /// Requires CBS material for either classic or sparse BR. With c=d, public lifting
    /// borrows the classic initializer; sparse BR requires explicit material via
    /// [`Self::try_with_public_lift`].
    ///
    /// # Correctness
    /// The server key must belong to this context's secrets and NTT representation,
    /// as required by [`OneHotCircuitBootstrapEvaluator::try_new`].
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        key_switching: &primus_tfhe_ntru::LweReturnParameters<T, LM>,
        server_key: &'a CircuitBootstrapServerKey<T>,
        lookup_table: &'a HighPrecisionLookupTable<T>,
    ) -> Result<Self, LookupTableError> {
        Self::try_from_server_key(context, key_switching, server_key, None, lookup_table)
    }

    /// Binds an explicit `NLEV[1]` with its own generation basis and noise parameters.
    /// This material takes precedence over the classic initializer when needed;
    /// tables with c>d ignore it and do not retain it.
    ///
    /// # Correctness
    /// The server key must satisfy [`Self::try_new`]'s contract and the lift must
    /// satisfy [`Self::try_from_parts`]'s secret, encoding and representation contract.
    pub fn try_with_public_lift(
        context: &'a TfheContext<T, Table, LM>,
        key_switching: &primus_tfhe_ntru::LweReturnParameters<T, LM>,
        server_key: &'a CircuitBootstrapServerKey<T>,
        lookup_table: &'a HighPrecisionLookupTable<T>,
        public_lift: NttPublicLift<'a, T>,
    ) -> Result<Self, LookupTableError> {
        Self::try_from_server_key(
            context,
            key_switching,
            server_key,
            Some(public_lift),
            lookup_table,
        )
    }

    fn try_from_server_key(
        context: &'a TfheContext<T, Table, LM>,
        key_switching: &primus_tfhe_ntru::LweReturnParameters<T, LM>,
        server_key: &'a CircuitBootstrapServerKey<T>,
        public_lift: Option<NttPublicLift<'a, T>>,
        lookup_table: &'a HighPrecisionLookupTable<T>,
    ) -> Result<Self, LookupTableError> {
        let circuit_key = server_key.circuit_bootstrap_key();
        Self::try_from_parts(
            context,
            key_switching,
            server_key.server_key().blind_rotation_key(),
            server_key.server_key().key_switching_key(),
            circuit_key,
            public_lift,
            lookup_table,
        )
    }

    /// Binds BR, LWE return, CBS and optional public-lift material to this table.
    /// `public_lift` pairs a transformed `NLEV[1]` view with its generation parameters.
    /// When [`HighPrecisionLookupTable::needs_public_lift`] is true, an explicit lift
    /// takes precedence; `None` borrows the classic initializer and its BR parameters.
    /// Sparse BR has no initializer and requires an explicit lift when c=d.
    /// Otherwise lift material is ignored and not retained. Its basis may differ from BR/CBS.
    /// Checks the lift's ring, modulus and exact transformed storage length.
    ///
    /// # Correctness
    /// All keys must share the actual source/target secrets and this context's
    /// transform representation; compatibility checks do not establish identity.
    /// The lift must encode one under the accumulator secret and supplied basis,
    /// with enough decomposition precision and noise margin for public LUT products.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table, LM>,
        key_switching: &primus_tfhe_ntru::LweReturnParameters<T, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        public_lift: Option<NttPublicLift<'a, T>>,
        lookup_table: &'a HighPrecisionLookupTable<T>,
    ) -> Result<Self, LookupTableError> {
        context
            .parameters()
            .check_lwe_return_key_with_parameters(key_switching, return_key)?;
        if !lookup_table.is_compatible(
            context.parameters().poly_length(),
            context.parameters().accumulator_ntru().cipher_modulus(),
            context.parameters().external_lwe().cipher_modulus(),
        ) {
            return Err(LookupTableError::IncompatibleParameters);
        }
        let public_lift = if lookup_table.needs_public_lift() {
            let (key, parameters) = public_lift
                .or_else(|| {
                    blind_rotation_key.classic_controls().map(|controls| {
                        (
                            controls.initializer(),
                            context.parameters().blind_rotation(),
                        )
                    })
                })
                .ok_or(LookupTableError::MissingPublicLiftKey)?;
            if parameters.poly_length() != context.parameters().poly_length()
                || parameters.encryption_parameters().cipher_modulus_value()
                    != context
                        .parameters()
                        .accumulator_ntru()
                        .cipher_modulus_value()
                || key.as_ref().len() != parameters.nlev_len()
            {
                return Err(LookupTableError::IncompatiblePublicLiftKey);
            }
            Some((key, parameters))
        } else {
            None
        };
        // The table was compiled with this q; use its own chunk encoding for one-hot CBS.
        let input_codec = RoundedCodec::new(
            lookup_table.plaintext_modulus(),
            context.parameters().external_lwe().cipher_modulus(),
        );
        let resources = context.bootstrap_resources(blind_rotation_key)?;
        let one_hot =
            OneHotCircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec)?;
        let sparse_pair = if lookup_table.config().input_chunk_count >= 2 {
            one_hot.new_sparse_pair_workspace(&resources)
        } else {
            None
        };
        let layout = lookup_table.layout;
        let n = layout.polynomial_length;
        let lengths =
            lookup_table.ntt_buffer_lengths(one_hot.parameters().output_basis().level_count())?;
        let lwe_return = LweReturnEvaluator::new(
            return_key,
            context.parameters().external_lwe().cipher_modulus(),
        );
        let mut evaluator = Self {
            context,
            lookup_table,
            public_lift,
            one_hot,
            sparse_pair,
            resources,
            scalar_return: lwe_return.new_scalar_workspace(),
            lwe_return,
            public_table_selectors: vec![T::ZERO; lengths.public_table_selectors]
                .into_boxed_slice(),
            encrypted_table_selectors: vec![T::ZERO; lengths.encrypted_table_selectors]
                .into_boxed_slice(),
            rotation_controls: vec![T::ZERO; lengths.rotation_controls].into_boxed_slice(),
            nonzero_selectors: vec![T::ZERO; lengths.nonzero_selectors].into_boxed_slice(),
            rotation_factors: vec![T::ZERO; lengths.rotation_factors].into_boxed_slice(),
            selected_tables: vec![T::ZERO; lengths.selected_tables].into_boxed_slice(),
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
            let chunk_place_value = 1usize << (i * layout.chunk_format.bits() as usize); // M^i
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
    /// Each output keeps its existing coefficient buffer. All input and output
    /// shapes are checked before evaluation begins.
    ///
    /// # Correctness
    /// Inherits one-hot CBS's key, canonical-input and quantized-phase guard
    /// requirements. Budget table products, rotations and Q-to-q/key-switch error
    /// in addition to CBS noise; parameter checks do not prove a decoding margin.
    /// Selectors and rotation controls are shared across outputs; their errors
    /// need not be independent.
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
        for (index, result) in output.iter_mut().enumerate() {
            self.select_table(index);
            self.rotate_selected_table();
            self.lwe_return.return_at_to(
                self.current.as_view(),
                0,
                result.as_mut_view(),
                &mut self.scalar_return,
            );
        }
    }

    /// Refreshes all input chunks in order. Sparse pairs share source-key
    /// traversal; projection and immediate consumption reuse the selector scratch.
    fn prepare_selectors(&mut self, input: &[LweCiphertext<T>]) {
        let table = self.lookup_table;
        let layout = table.layout;
        let mut chunks = 0..layout.config.input_chunk_count;
        // Borrow only selector outputs so the callback can consume each prepared
        // BR without exposing or replacing the shared one-hot/resource owners.
        let mut selectors = SelectorBuffers {
            public: &mut self.public_table_selectors,
            encrypted: &mut self.encrypted_table_selectors,
            rotations: &mut self.rotation_controls,
            nonzero: &mut self.nonzero_selectors,
        };
        let parameters = self.one_hot.parameters();
        while let Some(first) = chunks.next() {
            if let Some(pair) = self.sparse_pair.as_mut()
                && let Some(second) = chunks.next()
            {
                self.one_hot.with_sparse_pair(
                    [input[first].as_view(), input[second].as_view()],
                    pair,
                    &mut self.resources,
                    |index, projection| {
                        selectors.project_chunk(
                            [first, second][index],
                            layout,
                            &self.rotation_factors,
                            parameters,
                            self.context,
                            |output| match output {
                                SelectorOutput::Nlev(nlev) => {
                                    projection.project_to(Some(nlev), None)
                                }
                                SelectorOutput::Ngsw(ngsw) => {
                                    projection.project_to(None, Some(ngsw))
                                }
                            },
                        );
                    },
                );
                continue;
            }

            // Classic consumes only `first`; sparse reaches here for an odd tail.
            let input_chunk = input[first].as_view();
            selectors.project_chunk(
                first,
                layout,
                &self.rotation_factors,
                parameters,
                self.context,
                |output| match output {
                    SelectorOutput::Nlev(nlev) => {
                        self.one_hot
                            .one_hot_nlev_to(input_chunk, nlev, &mut self.resources)
                    }
                    SelectorOutput::Ngsw(ngsw) => {
                        self.one_hot
                            .one_hot_nonzero_ngsw_to(input_chunk, ngsw, &mut self.resources)
                    }
                },
            );
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
                self.resources.external_product_workspace(),
            );
            // Keep the new accumulator in `current` for both odd and even
            // rotation counts, without copying its N coefficients.
            core::mem::swap(&mut self.current, &mut self.product);
        }
    }

    /// Selects one output's polynomial into `current`. Without high chunks the
    /// sole public polynomial still needs lifting before coefficient rotations.
    fn select_table(&mut self, output_chunk: usize) {
        let table = self.lookup_table;
        let height = table.layout.table_chunk_count();
        let polynomials = table.output_polynomials(output_chunk);
        if height == 0 {
            self.lift_public_polynomial(&Polynomial::new(polynomials));
        } else {
            self.select_subtree(polynomials, height);
        }
    }

    /// Visits the complete tree depth first. A subtree spans M^height consecutive
    /// public polynomials; its most significant remaining chunk selects its root.
    /// Each encrypted layer owns M child slots. Recursive children use only lower
    /// layers, so completed siblings stay intact until this layer's CMux reads them.
    /// The root stays in `current`, ready for the next parent or coefficient rotation.
    fn select_subtree(&mut self, polynomials: &[T], height: usize) {
        if height == 1 {
            self.select_public_table(polynomials);
            return;
        }
        let layout = self.lookup_table.layout;
        let layer = height - 2;
        let n = layout.polynomial_length;
        for (branch, subtree) in polynomials
            .chunks_exact(polynomials.len() / layout.radix)
            .enumerate()
        {
            self.select_subtree(subtree, height - 1);
            let first = (layer * layout.radix + branch) * n;
            self.selected_tables[first..first + n].copy_from_slice(self.current.as_ref());
        }
        self.select_encrypted_table(layer);
    }

    /// Lifts a public polynomial under f with the bound `NLEV[1]` and its basis.
    /// Selection-tree products instead use the one-hot CBS output basis.
    fn lift_public_polynomial(&mut self, polynomial: &Polynomial<&[T]>) {
        // Binding requires this material exactly when c=d.
        let (key, parameters) = self.public_lift.as_ref().expect("bound public lift key");
        key.external_product_to(
            polynomial,
            &mut self.current,
            parameters.basis(),
            self.context
                .parameters()
                .accumulator_ntru()
                .cipher_modulus(),
            self.context.table(),
            self.resources.external_product_workspace(),
        );
    }

    /// Selects M public polynomials with full NLEV, including the default branch.
    /// This is always the first high chunk (index d); the CBS output basis applies.
    fn select_public_table(&mut self, polynomials: &[T]) {
        let selectors = &self.public_table_selectors;
        let basis = self.one_hot.parameters().output_basis();
        let selector_len = self.one_hot.ngsw_selector_len();
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        NttNlev::external_product_sum_to(
            NttNlevIter::new(selectors, selector_len),
            PolynomialIter::new(polynomials, self.lookup_table.layout.polynomial_length),
            self.current.as_mut_view(),
            basis,
            modulus,
            self.context.table(),
            self.resources.external_product_workspace(),
        );
    }

    /// Selects from the M completed children of one encrypted layer. Its controls
    /// correspond to input chunk d+1+layer. The read-only default and candidates
    /// remain intact while the fused kernel writes its result into `current`.
    fn select_encrypted_table(&mut self, layer: usize) {
        let layout = self.lookup_table.layout;
        let n = layout.polynomial_length;
        let selector_len = self.one_hot.ngsw_selector_len();
        let nonzero_len = (layout.radix - 1) * selector_len;
        let selectors =
            &self.encrypted_table_selectors[layer * nonzero_len..(layer + 1) * nonzero_len];
        let children_len = layout.radix * n;
        let children = &self.selected_tables[layer * children_len..(layer + 1) * children_len];
        let (default, candidates) = children.split_at(n);
        let basis = self.one_hot.parameters().output_basis();
        let modulus = self
            .context
            .parameters()
            .accumulator_ntru()
            .cipher_modulus();
        NttNgswCiphertext::cmux_k_to(
            NttNgswIter::new(selectors, selector_len),
            NtruCiphertext::new(default),
            NtruIter::new(candidates, n),
            self.current.as_mut_view(),
            basis,
            modulus,
            self.context.table(),
            self.resources.external_product_workspace(),
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
    parameters: &CbsGadgetParameters<T, BarrettModulus<T>>,
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
