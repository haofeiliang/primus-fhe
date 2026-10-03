//! Packed one-hot selectors from one fused blind rotation.

use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_ntru::{NlevCiphertext, NttNgswCiphertext};
use primus_ntt::MonomialNttTable;
pub use primus_tfhe_ntru::{OneHotBootstrapError, OneHotLookupTable};

use super::key::CircuitBootstrapBinding;

use crate::{
    CircuitBootstrapParameters, Evaluator, Lwe, ServerKey, TfheContext,
    bootstrap::{BlindRotationEngine, CircuitBootstrapResources},
};

/// One-hot extension of CBS for classic binary/ternary LWE secrets.
///
/// Input uses unsigned Rounded encoding with t=2*M, M=2^tau, tau>=1.
/// Full-output methods materialize all M selectors, including r=0;
/// [`Self::one_hot_nonzero_ngsw_to`] omits r=0 before projection and scheme switching.
/// NLEV outputs are coefficient polynomials under accumulator secret f at Q;
/// NGSW outputs use this backend's transform representation. Layout is `[selector][level][polynomial element]`,
/// in natural selector order and output-basis scalar order, with no padding.
/// Each call performs one BR and L full constant projections per selector.
/// Online calls overwrite outputs, reuse BR external-product scratch, and allocate nothing.
/// Ordinary CBS remains available through [`crate::CircuitBootstrapEvaluator`].
pub struct OneHotCircuitBootstrapEvaluator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    resources: CircuitBootstrapResources<'a, T, Table, LM>,
    circuit: CircuitBootstrapBinding<'a, T>,
    lookup_table: OneHotLookupTable<T>,
    trace_scratch: Vec<T>,
    projected: NlevCiphertext<Vec<T>>,
}

impl<'a, T, Table, LM> OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Binds standalone BR/projection resources and compiles the packed LUT.
    /// LWE return buffers are allocated only when recovering ordinary PBS.
    /// The input codec chooses t=2M at external q. Rejects sparse keys, absent CBS
    /// material, mismatched q, or packed geometry without enough guard capacity.
    ///
    /// # Correctness
    /// The context and server material must use the same secrets and transform
    /// representation. Shape checks cannot establish secret or representation identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        server_key: &'a ServerKey<T>,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<Self, OneHotBootstrapError> {
        Self::from_resources(
            CircuitBootstrapResources::Standalone(BlindRotationEngine::try_new(
                context, server_key,
            )?),
            input_codec,
        )
    }

    /// Consumes existing PBS workspace; allocates only the packed LUT and trace buffers.
    /// Inherits [`Self::try_new`]'s compatibility and error contracts.
    pub fn try_from_bootstrapper(
        pbs: Evaluator<'a, T, Table, LM>,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<Self, OneHotBootstrapError> {
        Self::from_resources(CircuitBootstrapResources::Bootstrapper(pbs), input_codec)
    }

    /// Binds CBS geometry once and allocates only its projection buffers.
    fn from_resources(
        resources: CircuitBootstrapResources<'a, T, Table, LM>,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<Self, OneHotBootstrapError> {
        let engine = resources.engine();
        let circuit = CircuitBootstrapBinding::try_new(
            engine.context.parameters(),
            engine.workspace.rotation.classic_controls(),
            engine.server_key.circuit_bootstrap_key(),
        )?;
        let lookup_table = OneHotLookupTable::try_new(
            engine.context.parameters(),
            circuit.parameters,
            input_codec,
        )?;
        let n = engine.context.parameters().poly_length().get();
        let projected = NlevCiphertext::zero(circuit.parameters.output_nlev_len());
        Ok(Self {
            resources,
            circuit,
            lookup_table,
            trace_scratch: vec![T::ZERO; 2 * n],
            projected,
        })
    }

    /// Borrows the classic BR initializer and controls established at construction.
    #[must_use]
    pub fn classic_controls(&self) -> crate::ClassicControls<'a, T> {
        self.circuit.classic_controls
    }

    /// Returns the packed LUT geometry, including selector count, stride and guard radius.
    #[must_use]
    pub fn lookup_table(&self) -> &OneHotLookupTable<T> {
        &self.lookup_table
    }

    /// Returns the shared CBS bases and accumulator layouts.
    #[must_use]
    pub fn parameters(&self) -> &'a CircuitBootstrapParameters<T> {
        self.circuit.parameters
    }

    /// Borrows the external-product workspace already used by one-hot CBS.
    /// Serial table products can reuse it between calls without allocation or reset.
    /// Every one-hot call overwrites its scratch before reading it.
    ///
    /// # Correctness
    /// Retain the workspace's polynomial length. It does not establish a product's
    /// key, modulus, basis or transform compatibility.
    #[must_use]
    pub fn external_product_workspace(
        &mut self,
    ) -> &mut primus_ntru::NttNtruExternalProductWorkspace<T> {
        let engine = self.resources.engine_mut();
        engine.workspace.rotation.external_product()
    }

    /// Returns the storage length of one transformed NGSW selector: L*N NTT ring elements.
    /// This is an element count, not a byte count or the length of the whole batch.
    #[must_use]
    pub fn ngsw_selector_len(&self) -> usize {
        self.parameters().output_nlev_len()
    }

    /// Returns the complete transformed NGSW batch length: M*L*N NTT ring elements.
    /// Includes every branch r=0..M-1 in selector-major order. The nonzero-only
    /// batch omits exactly one [`Self::ngsw_selector_len`] block.
    #[must_use]
    pub fn ngsw_batch_len(&self) -> usize {
        self.lookup_table.output_nlev_len()
    }

    /// Allocates M*L*N coefficients for all NLEV selectors. Reuse with [`Self::one_hot_nlev_to`].
    #[must_use]
    pub fn allocate_nlev_output(&self) -> Vec<T> {
        vec![T::ZERO; self.lookup_table.output_nlev_len()]
    }

    /// Allocates all transformed NGSW selectors: M*L*N elements.
    #[must_use]
    pub fn allocate_ngsw_output(&self) -> Vec<T> {
        vec![T::ZERO; self.ngsw_batch_len()]
    }

    /// Allocates (M-1)*L*N elements for selectors r=1..M-1.
    /// Reuse with [`Self::one_hot_nonzero_ngsw_to`].
    #[must_use]
    pub fn allocate_nonzero_ngsw_output(&self) -> Vec<T> {
        vec![T::ZERO; self.ngsw_batch_len() - self.ngsw_selector_len()]
    }

    /// Borrows ordinary PBS only when constructed from a complete bootstrapper,
    /// without allowing replacement of the bound evaluator.
    /// Standalone CBS has no client-return buffers and returns `None`.
    #[must_use]
    pub fn bootstrapper_mut(
        &mut self,
    ) -> Option<
        impl primus_tfhe::ProgrammableBootstrap<T>
        + primus_tfhe::ProgrammableBootstrapInterleaved<T>
        + use<'_, 'a, T, Table, LM>,
    > {
        self.resources.bootstrapper_mut()
    }

    /// Recovers ordinary PBS, allocating return buffers only for standalone CBS.
    /// A retained complete bootstrapper is recovered without allocation.
    #[must_use]
    pub fn into_bootstrapper(self) -> Evaluator<'a, T, Table, LM> {
        self.resources.into_bootstrapper()
    }

    /// Writes coefficient NLEV selectors only, without scheme switching.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_nlev_to(&mut self, input: Lwe<&[T]>, output: &mut [T]) {
        self.evaluate(input, 0, Some(output), None);
    }

    /// Writes transformed NGSW selectors only; retains no full NLEV output batch.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_ngsw_to(&mut self, input: Lwe<&[T]>, output: &mut [T]) {
        self.evaluate(input, 0, None, Some(output));
    }

    /// Writes only the transformed NGSW selectors for branches r=1..M-1.
    /// Output is packed as `[r-1][level][row element]`, with exactly (M-1)*L*N elements.
    /// For input m=0, all output target bits are zero. No r=0 projection or scheme
    /// switch is performed; the shared blind rotation and input guard are unchanged.
    /// Output is fully overwritten without allocation or prior clearing.
    ///
    /// # Correctness
    /// Inherits [`Self::one_hot_to`]'s input, representation and noise requirements.
    ///
    /// # Panics
    /// Rejects input dimension and exact output length before BR or output writes.
    pub fn one_hot_nonzero_ngsw_to(&mut self, input: Lwe<&[T]>, output: &mut [T]) {
        self.evaluate(input, 1, None, Some(output));
    }

    /// Writes both selector representations from the same BR and coefficient projections.
    /// NLEV row length is N; NGSW row length is N.
    /// NLEV phases target g_l*delta_r(m); NGSW phases target g_l*f*delta_r(m).
    ///
    /// # Correctness
    /// Input uses the bound external LWE secret and modulus q, with
    /// `m in 0..M` and phase `round(q*m/(2*M))+noise`. For the actual per-coordinate
    /// quantized phase, require `u_bar=S*m+W*e mod 2N` with integer `-A<=e<A`;
    /// see [`OneHotLookupTable`]. This includes encoding and quantization error,
    /// not just encryption noise. Coefficients must be canonical in their domains.
    /// The BR basis must resolve the smallest output gadget scale. Budget trace,
    /// decomposition and scheme-switch f/f² amplification separately. NTT trace
    /// uses modular inverse halving. Geometry checks are not noise or security
    /// certification. See [`CircuitBootstrapParameters`].
    ///
    /// # Panics
    /// Rejects input dimension and exact output lengths before BR or output writes.
    /// Output buffers contain no padding and need no prior reset.
    pub fn one_hot_to(&mut self, input: Lwe<&[T]>, nlev_output: &mut [T], ngsw_output: &mut [T]) {
        self.evaluate(input, 0, Some(nlev_output), Some(ngsw_output));
    }

    /// Writes all M coefficient NLEVs and only the r=1..M-1 transformed NGSWs.
    /// Shares one blind rotation and each coefficient projection; branch zero
    /// is projected for NLEV but never scheme-switched. Buffer layouts and
    /// correctness requirements are those of [`Self::one_hot_nlev_to`] and
    /// [`Self::one_hot_nonzero_ngsw_to`].
    ///
    /// # Panics
    /// Rejects input dimension and exact output lengths before any writes.
    pub fn one_hot_nlev_and_nonzero_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        nlev_output: &mut [T],
        ngsw_output: &mut [T],
    ) {
        self.evaluate(input, 1, Some(nlev_output), Some(ngsw_output));
    }

    /// NLEV, when requested, always contains every branch. NGSW may omit zero;
    /// its compact slot is r-first_ngsw_selector. Project each needed branch
    /// once and retain no extra full NLEV batch for NGSW-only calls.
    fn evaluate(
        &mut self,
        input: Lwe<&[T]>,
        first_ngsw_selector: usize,
        mut nlev_output: Option<&mut [T]>,
        mut ngsw_output: Option<&mut [T]>,
    ) {
        let ngsw_len = self.ngsw_selector_len();
        let engine = self.resources.engine_mut();
        let tfhe = engine.context.parameters();
        let parameters = self.circuit.parameters;
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension().get(),
            "one-hot input dimension mismatch"
        );

        let nlev_len = parameters.output_nlev_len();
        let selector_count = self.lookup_table.selector_count();
        if let Some(output) = &nlev_output {
            assert_eq!(
                output.len(),
                selector_count * nlev_len,
                "one-hot NLEV output length mismatch"
            );
        }
        if let Some(output) = &ngsw_output {
            assert_eq!(
                output.len(),
                (selector_count - first_ngsw_selector) * ngsw_len,
                "one-hot NGSW output length mismatch"
            );
        }

        engine.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.rotation_step(),
        );

        // Without NLEV, omit branch zero before projection as well as conversion.
        let first_selector = if nlev_output.is_some() {
            0
        } else {
            first_ngsw_selector
        };
        for selector in first_selector..selector_count {
            // Negative BR places selector r at -r*S+l, including its negacyclic
            // sign. Rotate by +r*S first; prefix projection then shifts by -l.
            // General BR tails are nonzero: prefix expansion is not valid here.
            engine.workspace.current.mul_monomial_to(
                selector * self.lookup_table.selector_stride(),
                &mut engine.workspace.scratch,
                tfhe.accumulator_ntru().cipher_modulus(),
            );
            let projected = match nlev_output.as_deref_mut() {
                Some(output) => &mut output[selector * nlev_len..(selector + 1) * nlev_len],
                None => self.projected.as_mut(),
            };
            self.circuit
                .key
                .trace_key()
                .project_prefix_coefficients_with_scratch_to(
                    &engine.workspace.scratch,
                    self.lookup_table.level_count().get(),
                    projected,
                    tfhe.accumulator_ntru().cipher_modulus(),
                    engine.context.table(),
                    &mut self.trace_scratch,
                    engine.workspace.rotation.external_product(),
                );
            if let Some(output) = ngsw_output
                .as_deref_mut()
                .filter(|_| selector >= first_ngsw_selector)
            {
                let output_index = selector - first_ngsw_selector;
                self.circuit.key.scheme_switch_key().apply_to(
                    &NlevCiphertext::new(&*projected),
                    &mut NttNgswCiphertext::new(
                        &mut output[output_index * ngsw_len..(output_index + 1) * ngsw_len],
                    ),
                    tfhe.accumulator_ntru().cipher_modulus(),
                    engine.context.table(),
                    engine.workspace.rotation.external_product(),
                );
            }
        }
    }
}
