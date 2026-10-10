use primus_encoding::RoundedCodec;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_lattice::{
    ngsw::FourierNgswIter,
    nlev::{FourierNlev, FourierNlevIter},
    ntru::NtruIter,
};
use primus_ntru::{FourierNgswCiphertext, NlevParameters, NtruCiphertext};
use primus_poly::{FourierPolynomialIter, FourierPolynomialIterMut, Polynomial, PolynomialIter};
use primus_reduce::RingContext;
use primus_tfhe::LweCiphertext;
use primus_tfhe_ntru::{LweReturnBatchWorkspace, LweReturnEvaluator};
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapServerKey, TfheContext,
    circuit_bootstrap::{CircuitBootstrapKey, OneHotCircuitBootstrapEvaluator},
    key::BlindRotationKey,
};
use selectors::SelectorBuffers;
use std::ops::Range;

use crate::{
    HighPrecisionLookupTable, LookupTableError,
    evaluation::{SelectorOutput, check_io},
};

mod context;
mod selectors;
pub use context::{FourierHighPrecLutContext, FourierHighPrecLutServerKey, FourierPublicLiftKey};

/// Borrowed `NLEV[1]` view and its generation parameters for public polynomial lifting.
/// This tuple owns no buffers and performs no validation; binding through
/// [`FourierLookupTableEvaluator::try_from_parts`] checks the ring and storage layout.
/// The caller guarantees the encoded one, actual secret, basis and transform identity.
pub type FourierPublicLift<'a, T> = (
    FourierNlev<&'a [Complex64]>,
    &'a NlevParameters<T, primus_modulus::NativeModulus<T>>,
);

/// Native-torus Fourier high-precision lookup bound to one public table and CBS-enabled key.
///
/// Generates one batch of selectors per input chunk, shared by all outputs.
/// Every output executes the complete selection tree: full NLEV at its first
/// layer, then nonzero NGSW for each later layer. Repeated tables do not skip work.
/// Low chunks retain aggregated rotation controls; shared selectors and controls
/// can correlate output errors. Sparse BR prepares input chunks in pairs, with
/// one extra input state only when at least two chunks need BR.
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
    resources: primus_tfhe_ntru_fourier::bootstrap::BootstrapResources<'a, T, Table, LM>,
    one_hot: OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
    // One extra input state; transform, product and projection scratch stay shared.
    sparse_pair: Option<primus_tfhe_ntru_fourier::sparse::SparseBlindRotationPairWorkspace<T>>,
    // Present only for c=d (no selection layer), with its own basis.
    public_lift: Option<FourierPublicLift<'a, T>>,
    lwe_return: LweReturnEvaluator<'a, T, LM>,
    batch_return: LweReturnBatchWorkspace<T>,
    // [branch][level][Fourier value]: full selectors for public choices.
    public_table_selectors: Box<[Complex64]>,
    // First high chunk's coefficient NLEVs, transformed once per request.
    public_selector_coefficients: Box<[T]>,
    // [high chunk after the first][r-1][level][Fourier value]: nonzero selectors for encrypted choices.
    encrypted_table_selectors: Box<[Complex64]>,
    // [low chunk][level][Fourier value]: one NGSW[X^(-m_i*M^i)] per low chunk.
    rotation_controls: Box<[Complex64]>,
    // One chunk's M-1 NGSW selectors for r=1..M-1, reused for each rotation control.
    nonzero_selectors: Box<[Complex64]>,
    // [low chunk i][nonzero digit k][Fourier value] of X^(-k*M^i)-1 at integer scale.
    rotation_factors: Box<[Complex64]>,
    // Trivial NGSW[1] at torus scale, with one constant g_l polynomial per row.
    gadget_one: Box<[Complex64]>,
    // [encrypted layer][branch][coefficient]: M children, reused after their parent.
    // Only M*(h-1) NTRUs are retained, not the complete intermediate tree.
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
    /// Requires CBS material for either classic or sparse BR. With c=d, public lifting
    /// borrows the classic initializer; sparse BR requires explicit material via
    /// [`Self::try_with_public_lift`].
    ///
    /// # Correctness
    /// The server key must belong to this context's secrets and exact FFT table instance,
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
        public_lift: FourierPublicLift<'a, T>,
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
        public_lift: Option<FourierPublicLift<'a, T>>,
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
    /// exact FFT table instance; compatibility checks do not establish identity.
    /// The lift must encode one under the accumulator secret and supplied basis,
    /// with enough decomposition precision and noise margin for public LUT products.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table, LM>,
        key_switching: &primus_tfhe_ntru::LweReturnParameters<T, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        public_lift: Option<FourierPublicLift<'a, T>>,
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
                || key.as_ref().len() != parameters.fourier_nlev_len()
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
        let lengths = lookup_table
            .fourier_buffer_lengths(one_hot.parameters().output_basis().decompose_length())?;
        let lwe_return = LweReturnEvaluator::new(
            return_key,
            context.parameters().external_lwe().cipher_modulus(),
        );
        let mut evaluator = Self {
            context,
            lookup_table,
            public_lift,
            one_hot,
            resources,
            sparse_pair,
            batch_return: lwe_return.new_batch_workspace(),
            lwe_return,
            public_table_selectors: vec![Complex64::default(); lengths.public_table_selectors]
                .into_boxed_slice(),
            public_selector_coefficients: vec![T::ZERO; lengths.public_selector_coefficients]
                .into_boxed_slice(),
            encrypted_table_selectors: vec![
                Complex64::default();
                lengths.encrypted_table_selectors
            ]
            .into_boxed_slice(),
            rotation_controls: vec![Complex64::default(); lengths.rotation_controls]
                .into_boxed_slice(),
            nonzero_selectors: vec![Complex64::default(); lengths.nonzero_selectors]
                .into_boxed_slice(),
            rotation_factors: vec![Complex64::default(); lengths.rotation_factors]
                .into_boxed_slice(),
            gadget_one: vec![Complex64::default(); lengths.gadget_one].into_boxed_slice(),
            selected_tables: vec![T::ZERO; lengths.selected_tables].into_boxed_slice(),
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
            let chunk_place_value = 1usize << (i * layout.chunk_format.bits() as usize); // M^i
            for (chunk_value, mut factor) in
                (1..layout.radix).zip(FourierPolynomialIterMut::new(factors, row_len))
            {
                let exponent = chunk_value * chunk_place_value;
                // 0 < exponent < N, so X^(-exponent)-1 = -X^(N-exponent)-1.
                // Integer scale is required; torus scale would rescale controls.
                coefficients.fill(T::ZERO);
                coefficients[0] = T::MAX;
                coefficients[n - exponent] = T::MAX;
                self.resources
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
            self.resources
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
    /// Each output keeps its existing coefficient buffer. All input and output
    /// shapes are checked before evaluation begins.
    ///
    /// # Correctness
    /// Inherits one-hot CBS's key, canonical-input and quantized-phase guard
    /// requirements. Budget table products, rotations and Q-to-q/key-switch error
    /// in addition to CBS noise, native trace rounding and FFT error; parameter
    /// checks do not prove a decoding margin. Selectors and rotation controls
    /// are shared across outputs; their errors need not be independent.
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
        let capacity = self.batch_return.batch_capacity();
        for (tile, outputs) in output.chunks_mut(capacity).enumerate() {
            let first = tile * capacity;
            self.batch_return.begin_batch();
            self.prepare_output_returns(first..first + outputs.len());
            self.lwe_return
                .return_batch_to(outputs, &mut self.batch_return);
        }
    }

    /// Prepares a bounded tile, including a possibly shorter final tile. Selection and
    /// rotation reuse polynomial scratch but preserve filled return slots.
    fn prepare_output_returns(&mut self, outputs: Range<usize>) {
        for output in outputs {
            self.select_table(output);
            self.rotate_selected_table();
            self.lwe_return
                .append_at(self.current.as_view(), 0, &mut self.batch_return);
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
            coefficients: &mut self.public_selector_coefficients,
            rotation_factors: &self.rotation_factors,
            gadget_one: &self.gadget_one,
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
                            parameters,
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
            selectors.project_chunk(first, layout, parameters, |output| {
                match output {
                    SelectorOutput::Nlev(nlev) => {
                        self.one_hot
                            .one_hot_nlev_to(input_chunk, nlev, &mut self.resources)
                    }
                    SelectorOutput::Ngsw(ngsw) => {
                        self.one_hot
                            .one_hot_nonzero_ngsw_to(input_chunk, ngsw, &mut self.resources)
                    }
                };
                self.resources.external_product_workspaces().0
            });
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
            let (fft, external_product) = self.resources.external_product_workspaces();
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
        let (fft, external_product) = self.resources.external_product_workspaces();
        key.external_product_to(
            polynomial,
            &mut self.current,
            parameters.basis(),
            fft,
            external_product,
        );
    }

    /// Selects M public polynomials with full NLEV, including the default branch.
    /// This is always the first high chunk (index d); the CBS output basis applies.
    fn select_public_table(&mut self, polynomials: &[T]) {
        let selectors = &self.public_table_selectors;
        let basis = self.one_hot.parameters().output_basis();
        let selector_len = self.one_hot.ngsw_selector_len();
        let (fft, external_product) = self.resources.external_product_workspaces();
        FourierNlev::external_product_sum_to(
            FourierNlevIter::new(selectors, selector_len),
            PolynomialIter::new(polynomials, self.lookup_table.layout.polynomial_length),
            self.current.as_mut_view(),
            basis,
            fft,
            external_product,
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
        let (fft, external_product) = self.resources.external_product_workspaces();
        FourierNgswCiphertext::cmux_k_to(
            FourierNgswIter::new(selectors, selector_len),
            NtruCiphertext::new(default),
            NtruIter::new(candidates, n),
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
