//! Packed one-hot selectors from one fused blind rotation.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_ntru::{FourierNgswCiphertext, NlevCiphertext, NtruCiphertext};
use primus_tfhe::LweCiphertext;
pub use primus_tfhe_ntru::{OneHotBootstrapError, OneHotLookupTable};

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, Evaluator, ServerKey, TfheContext,
    TfheEvaluationError, blind_rotation::blind_rotate_lookup_table_to,
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
pub struct OneHotCircuitBootstrapEvaluator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    pbs: Evaluator<'a, T, Table, LM>,
    circuit_key: &'a CircuitBootstrapKey<T>,
    lookup_table: OneHotLookupTable<T>,
    trace_scratch: Vec<T>,
    projected: NlevCiphertext<Vec<T>>,
}

impl<'a, T, Table, LM> OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Binds the context and its CBS-enabled server key and compiles the packed LUT.
    /// Rejects sparse keys, absent CBS material, incompatible parameters or geometry.
    ///
    /// # Correctness
    /// The context and server material must use the same secrets and transform
    /// representation. Fourier values additionally require the generation FFT table
    /// instance. Shape checks cannot establish secret or representation identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, OneHotBootstrapError> {
        if server_key.sparse_bootstrapping_key().is_some() {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping.into());
        }
        Self::try_from_bootstrapper(Evaluator::try_new(context, server_key)?)
    }

    /// Consumes existing PBS workspace; allocates only the packed LUT and trace buffers.
    /// Inherits [`Self::try_new`]'s compatibility and error contracts.
    pub fn try_from_bootstrapper(
        pbs: Evaluator<'a, T, Table, LM>,
    ) -> Result<Self, OneHotBootstrapError> {
        if pbs.server_key.sparse_bootstrapping_key().is_some() {
            return Err(TfheEvaluationError::UnsupportedSparseBootstrapping.into());
        }
        let circuit_key = pbs
            .server_key
            .circuit_bootstrap_key()
            .ok_or(TfheEvaluationError::MissingCircuitBootstrapKey)?;
        let lookup_table =
            OneHotLookupTable::try_new(pbs.context.parameters(), circuit_key.parameters())?;
        if lookup_table.output_nlev_len() / 2 > isize::MAX as usize / size_of::<Complex64>() {
            return Err(OneHotBootstrapError::StorageSizeOverflow);
        }
        let n = pbs.context.parameters().poly_length().get();
        Ok(Self {
            pbs,
            circuit_key,
            lookup_table,
            trace_scratch: vec![T::ZERO; 2 * n],
            projected: NlevCiphertext::zero(circuit_key.parameters().output_nlev_len()),
        })
    }

    /// Returns the packed LUT geometry, including selector count, stride and guard radius.
    #[must_use]
    pub fn lookup_table(&self) -> &OneHotLookupTable<T> {
        &self.lookup_table
    }

    /// Maximum number of NTRU samples prepared before returning one LWE batch.
    /// The bound PBS evaluator owns the buffers; callers cannot replace them.
    #[must_use]
    pub fn lwe_return_batch_capacity(&self) -> usize {
        self.pbs.lwe_return_batch_capacity()
    }

    /// Converts/extracts coefficient `index` into return slot `slot`, without allocation.
    /// The input buffer can be overwritten immediately afterward. One-hot generation
    /// and external products leave prepared slots intact; interleaved PBS may overwrite
    /// them, so finish a pending batch before borrowing ordinary PBS operations.
    ///
    /// # Correctness
    /// Input must be a canonical coefficient NTRU under this evaluator's ring secret
    /// at Q. The key and noise requirements of
    /// [`NtruLweKeySwitchingKey::modulus_switch_extract_at_to`](primus_ntru::NtruLweKeySwitchingKey::modulus_switch_extract_at_to)
    /// apply. This binds the return key and q; it does not check source secret identity.
    ///
    /// # Panics
    /// Rejects an invalid input length, coefficient index or slot before slot writes.
    pub fn prepare_lwe_return_at(
        &mut self,
        input: NtruCiphertext<&[T]>,
        index: usize,
        slot: usize,
    ) {
        self.pbs.prepare_lwe_return_at(input, index, slot);
    }

    /// Returns prepared slots `0..outputs.len()` in order under the external LWE secret.
    /// Reuses PBS's buffers without allocation or clearing. Slots remain intact;
    /// a short final batch ignores later slots, and an empty batch writes nothing.
    ///
    /// # Correctness
    /// Prepare every consumed slot through [`Self::prepare_lwe_return_at`] for the
    /// current batch. No filled-slot count is tracked; fresh or stale storage does
    /// not establish a valid sample. The return noise requirements of
    /// [`NtruLweKeySwitchingKey::key_switch_extracted_batch_to`](primus_ntru::NtruLweKeySwitchingKey::key_switch_extracted_batch_to)
    /// apply.
    ///
    /// # Panics
    /// Rejects a count above [`Self::lwe_return_batch_capacity`] or any incompatible
    /// output dimension before output/scratch writes.
    pub fn return_lwe_batch_to(&mut self, outputs: &mut [LweCiphertext<T>]) {
        self.pbs.return_lwe_batch_to(outputs);
    }

    /// Returns the shared CBS bases and accumulator layouts.
    #[must_use]
    pub fn parameters(&self) -> &'a CircuitBootstrapParameters<T> {
        self.circuit_key.parameters()
    }

    /// Borrows the FFT engine and external-product workspace already used by one-hot CBS.
    /// Serial table products can reuse them between calls without allocation or reset.
    /// Every one-hot call overwrites its scratch before reading it.
    ///
    /// # Correctness
    /// Retain the engine's table identity and both workspaces' polynomial lengths.
    /// These buffers do not establish a product's key, basis or scale compatibility.
    #[must_use]
    pub fn external_product_workspaces(
        &mut self,
    ) -> (
        &mut primus_fft::FftEngine<'a, Table>,
        &mut primus_ntru::FourierNtruExternalProductWorkspace<T>,
    ) {
        (
            &mut self.pbs.fft,
            self.pbs.blind_rotation.rotation.external_product(),
        )
    }

    /// Returns the storage length of one transformed NGSW selector: L*(N/2) complex values.
    /// This is an element count, not a byte count or the length of the whole batch.
    #[must_use]
    pub fn ngsw_selector_len(&self) -> usize {
        self.parameters().output_fourier_nlev_len()
    }

    /// Returns the complete transformed NGSW batch length: M*L*(N/2) complex values.
    /// Includes every branch r=0..M-1 in selector-major order. The nonzero-only
    /// batch omits exactly one [`Self::ngsw_selector_len`] block.
    #[must_use]
    pub fn ngsw_batch_len(&self) -> usize {
        self.lookup_table.output_nlev_len() / 2
    }

    /// Allocates M*L*N coefficients for all NLEV selectors. Reuse with [`Self::one_hot_nlev_to`].
    #[must_use]
    pub fn allocate_nlev_output(&self) -> Vec<T> {
        vec![T::ZERO; self.lookup_table.output_nlev_len()]
    }

    /// Allocates all transformed NGSW selectors: M*L*(N/2) elements.
    #[must_use]
    pub fn allocate_ngsw_output(&self) -> Vec<Complex64> {
        vec![Complex64::default(); self.ngsw_batch_len()]
    }

    /// Allocates (M-1)*L*N/2 complex values for selectors r=1..M-1.
    /// Reuse with [`Self::one_hot_nonzero_ngsw_to`].
    #[must_use]
    pub fn allocate_nonzero_ngsw_output(&self) -> Vec<Complex64> {
        vec![Complex64::default(); self.ngsw_batch_len() - self.ngsw_selector_len()]
    }

    /// Borrows ordinary PBS operations without allocation or changing the bound resources.
    #[must_use]
    pub fn bootstrapper_mut(
        &mut self,
    ) -> impl primus_tfhe::ProgrammableBootstrap<T>
    + primus_tfhe::ProgrammableBootstrapInterleaved<T>
    + use<'_, 'a, T, Table, LM> {
        &mut self.pbs
    }

    /// Releases one-hot buffers and recovers the PBS workspace without allocation.
    #[must_use]
    pub fn into_bootstrapper(self) -> Evaluator<'a, T, Table, LM> {
        self.pbs
    }

    /// Writes coefficient NLEV selectors only, without scheme switching.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_nlev_to(&mut self, input: &LweCiphertext<T>, output: &mut [T]) {
        self.evaluate(input, 0, Some(output), None);
    }

    /// Writes transformed NGSW selectors only; retains no full NLEV output batch.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_ngsw_to(&mut self, input: &LweCiphertext<T>, output: &mut [Complex64]) {
        self.evaluate(input, 0, None, Some(output));
    }

    /// Writes only the transformed NGSW selectors for branches r=1..M-1.
    /// Output is packed as `[r-1][level][row element]`, with exactly (M-1)*L*N/2 complex values.
    /// For input m=0, all output target bits are zero. No r=0 projection or scheme
    /// switch is performed; the shared blind rotation and input guard are unchanged.
    /// Output is fully overwritten without allocation or prior clearing.
    ///
    /// # Correctness
    /// Inherits [`Self::one_hot_to`]'s input, representation and noise requirements.
    ///
    /// # Panics
    /// Rejects input dimension and exact output length before BR or output writes.
    pub fn one_hot_nonzero_ngsw_to(&mut self, input: &LweCiphertext<T>, output: &mut [Complex64]) {
        self.evaluate(input, 1, None, Some(output));
    }

    /// Writes both selector representations from the same BR and coefficient projections.
    /// NLEV row length is N; NGSW row length is N/2.
    /// NLEV phases target g_l*delta_r(m); NGSW phases target g_l*f*delta_r(m).
    ///
    /// # Correctness
    /// Input uses the bound external LWE secret and modulus q, with
    /// `m in 0..M` and phase `round(q*m/(2*M))+noise`. For the actual per-coordinate
    /// quantized phase, require `u_bar=S*m+W*e mod 2N` with integer `-A<=e<A`;
    /// see [`OneHotLookupTable`]. This includes encoding and quantization error,
    /// not just encryption noise. Coefficients must be canonical in their domains.
    /// The BR basis must resolve the smallest output gadget scale. Budget trace,
    /// decomposition and scheme-switch f/f² amplification separately; Fourier
    /// also uses native floor halving and FFT rounding. Geometry checks are not
    /// noise or security certification. See [`CircuitBootstrapParameters`].
    ///
    /// # Panics
    /// Rejects input dimension and exact output lengths before BR or output writes.
    /// Output buffers contain no padding and need no prior reset.
    pub fn one_hot_to(
        &mut self,
        input: &LweCiphertext<T>,
        nlev_output: &mut [T],
        ngsw_output: &mut [Complex64],
    ) {
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
        input: &LweCiphertext<T>,
        nlev_output: &mut [T],
        ngsw_output: &mut [Complex64],
    ) {
        self.evaluate(input, 1, Some(nlev_output), Some(ngsw_output));
    }

    /// NLEV, when requested, always contains every branch. NGSW may omit zero;
    /// its compact slot is r-first_ngsw_selector. Project each needed branch
    /// once and retain no extra full NLEV batch for NGSW-only calls.
    fn evaluate(
        &mut self,
        input: &LweCiphertext<T>,
        first_ngsw_selector: usize,
        mut nlev_output: Option<&mut [T]>,
        mut ngsw_output: Option<&mut [Complex64]>,
    ) {
        let tfhe = self.pbs.context.parameters();
        let parameters = self.circuit_key.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension().get(),
            "one-hot input dimension mismatch"
        );

        let nlev_len = parameters.output_nlev_len();
        let ngsw_len = self.ngsw_selector_len();
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

        blind_rotate_lookup_table_to(
            self.pbs.server_key,
            input.as_view(),
            self.lookup_table.polynomial().as_view(),
            self.lookup_table.rotation_step(),
            &mut self.pbs.blind_rotation,
            tfhe,
            &mut self.pbs.fft,
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
            self.pbs.blind_rotation.current.mul_monomial_to(
                selector * self.lookup_table.selector_stride(),
                &mut self.pbs.blind_rotation.scratch,
                tfhe.accumulator_ntru().cipher_modulus(),
            );
            let projected = match nlev_output.as_deref_mut() {
                Some(output) => &mut output[selector * nlev_len..(selector + 1) * nlev_len],
                None => self.projected.as_mut(),
            };
            self.circuit_key
                .trace_key()
                .project_prefix_coefficients_with_scratch_to(
                    &self.pbs.blind_rotation.scratch,
                    self.lookup_table.level_count().get(),
                    projected,
                    &mut self.pbs.fft,
                    &mut self.trace_scratch,
                    self.pbs.blind_rotation.rotation.external_product(),
                );
            if let Some(output) = ngsw_output
                .as_deref_mut()
                .filter(|_| selector >= first_ngsw_selector)
            {
                let output_index = selector - first_ngsw_selector;
                self.circuit_key.scheme_switch_key().apply_to(
                    &NlevCiphertext::new(&*projected),
                    &mut FourierNgswCiphertext::new(
                        &mut output[output_index * ngsw_len..(output_index + 1) * ngsw_len],
                    ),
                    &mut self.pbs.fft,
                    self.pbs.blind_rotation.rotation.external_product(),
                );
            }
        }
    }
}
