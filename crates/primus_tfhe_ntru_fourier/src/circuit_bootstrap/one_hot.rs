//! Packed one-hot selectors from one fused blind rotation.

use primus_encoding::RoundedCodec;
use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_ntru::{FourierNgswCiphertext, NlevCiphertext};
pub use primus_tfhe_ntru::{OneHotBootstrapError, OneHotLookupTable};

mod pair;
pub use pair::OneHotProjection;

use crate::{
    BootstrapResources, CircuitBootstrapKey, CircuitBootstrapParameters, Lwe, TfheContext,
};

/// One-hot extension of CBS for classic binary/ternary and sparse binary BR.
///
/// Input uses unsigned Rounded encoding with t=2*M, M=2^tau, tau>=1.
/// Full-output methods materialize all M selectors, including r=0;
/// [`Self::one_hot_nonzero_ngsw_to`] omits r=0 before projection and scheme switching.
/// NLEV outputs are coefficient polynomials under accumulator secret f at Q;
/// NGSW outputs use this backend's transform representation. Layout is `[selector][level][polynomial element]`,
/// in natural selector order and output-basis scalar order, with no padding.
/// Each call performs one BR and L full constant projections per selector.
/// Online calls overwrite outputs, reuse BR external-product scratch, and allocate nothing.
/// Owns only the packed LUT and projection buffers; common BR/FFT/EP resources
/// are borrowed per operation and no return buffers are owned.
/// Ordinary CBS remains available through [`crate::CircuitBootstrapEvaluator`].
pub struct OneHotCircuitBootstrapEvaluator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    context: &'a TfheContext<T, Table, LM>,
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
    /// Compiles the packed LUT and allocates projection buffers without retaining
    /// a borrow of the resource owner. Online calls accept resources made from
    /// the same context.
    ///
    /// # Correctness
    /// The circuit key must share the resources' actual accumulator secret and
    /// FFT table instance; compatibility checks do not establish these identities.
    /// Switching between classic and sparse resources must preserve both secrets.
    pub fn try_new(
        resources: &BootstrapResources<'a, T, Table, LM>,
        circuit_key: &'a CircuitBootstrapKey<T>,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<Self, OneHotBootstrapError> {
        circuit_key.check_parameters(resources.context.parameters())?;
        let lookup_table = OneHotLookupTable::try_new(
            resources.context.parameters(),
            circuit_key.parameters(),
            input_codec,
        )?;
        if lookup_table.output_nlev_len() / 2 > isize::MAX as usize / size_of::<Complex64>() {
            return Err(OneHotBootstrapError::StorageSizeOverflow);
        }
        let n = resources.context.parameters().poly_length().get();
        let projected = NlevCiphertext::zero(circuit_key.parameters().output_nlev_len());
        Ok(Self {
            context: resources.context,
            circuit_key,
            lookup_table,
            trace_scratch: vec![T::ZERO; 2 * n],
            projected,
        })
    }

    /// Returns the packed LUT geometry, including selector count, stride and guard radius.
    #[must_use]
    pub fn lookup_table(&self) -> &OneHotLookupTable<T> {
        &self.lookup_table
    }

    /// Returns the shared CBS bases and accumulator layouts.
    #[must_use]
    pub fn parameters(&self) -> &'a CircuitBootstrapParameters<T> {
        self.circuit_key.parameters()
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

    /// Writes coefficient NLEV selectors only, without scheme switching.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_nlev_to(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut [T],
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        self.evaluate(input, 0, Some(output), None, resources);
    }

    /// Writes transformed NGSW selectors only; retains no full NLEV output batch.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut [Complex64],
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        self.evaluate(input, 0, None, Some(output), resources);
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
    /// Rejects a different context binding, input dimension or exact output length before BR or output writes.
    pub fn one_hot_nonzero_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        output: &mut [Complex64],
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        self.evaluate(input, 1, None, Some(output), resources);
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
    /// Rejects a different context binding, input dimension or exact output lengths before BR or output writes.
    /// Output buffers contain no padding and need no prior reset.
    pub fn one_hot_to(
        &mut self,
        input: Lwe<&[T]>,
        nlev_output: &mut [T],
        ngsw_output: &mut [Complex64],
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        self.evaluate(input, 0, Some(nlev_output), Some(ngsw_output), resources);
    }

    /// Writes all M coefficient NLEVs and only the r=1..M-1 transformed NGSWs.
    /// Shares one blind rotation and each coefficient projection; branch zero
    /// is projected for NLEV but never scheme-switched. Buffer layouts and
    /// correctness requirements are those of [`Self::one_hot_nlev_to`] and
    /// [`Self::one_hot_nonzero_ngsw_to`].
    ///
    /// # Panics
    /// Rejects a different context binding, input dimension or exact output lengths before any writes.
    pub fn one_hot_nlev_and_nonzero_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        nlev_output: &mut [T],
        ngsw_output: &mut [Complex64],
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        self.evaluate(input, 1, Some(nlev_output), Some(ngsw_output), resources);
    }

    /// NLEV, when requested, always contains every branch. NGSW may omit zero;
    /// its compact slot is r-first_ngsw_selector. Project each needed branch
    /// once and retain no extra full NLEV batch for NGSW-only calls.
    fn evaluate(
        &mut self,
        input: Lwe<&[T]>,
        first_ngsw_selector: usize,
        nlev_output: Option<&mut [T]>,
        ngsw_output: Option<&mut [Complex64]>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        resources.check_context(self.context);
        assert_eq!(
            input.dimension(),
            resources
                .context
                .parameters()
                .external_lwe_dimension()
                .get(),
            "one-hot input dimension mismatch"
        );
        self.check_output_lengths(
            first_ngsw_selector,
            nlev_output.as_deref(),
            ngsw_output.as_deref(),
        );

        resources.blind_rotate(
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.rotation_step(),
        );

        self.project(first_ngsw_selector, nlev_output, ngsw_output, resources);
    }

    // Both ordinary and paired projection boundaries require exact output batches.
    fn check_output_lengths(
        &self,
        first_ngsw_selector: usize,
        nlev: Option<&[T]>,
        ngsw: Option<&[Complex64]>,
    ) {
        if let Some(output) = nlev {
            assert_eq!(
                output.len(),
                self.lookup_table.output_nlev_len(),
                "one-hot NLEV output length mismatch"
            );
        }
        if let Some(output) = ngsw {
            assert_eq!(
                output.len(),
                (self.lookup_table.selector_count() - first_ngsw_selector)
                    * self.ngsw_selector_len(),
                "one-hot NGSW output length mismatch"
            );
        }
    }

    /// Project an already prepared BR result, retaining the shared scratch contract.
    fn project(
        &mut self,
        first_ngsw_selector: usize,
        mut nlev_output: Option<&mut [T]>,
        mut ngsw_output: Option<&mut [Complex64]>,
        resources: &mut BootstrapResources<'a, T, Table, LM>,
    ) {
        let tfhe = resources.context.parameters();
        let ngsw_len = self.ngsw_selector_len();
        let nlev_len = self.circuit_key.parameters().output_nlev_len();
        let selector_count = self.lookup_table.selector_count();
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
            resources.workspace.current.mul_monomial_to(
                selector * self.lookup_table.selector_stride(),
                &mut resources.workspace.scratch,
                tfhe.accumulator_ntru().cipher_modulus(),
            );
            let projected = match nlev_output.as_deref_mut() {
                Some(output) => &mut output[selector * nlev_len..(selector + 1) * nlev_len],
                None => self.projected.as_mut(),
            };
            self.circuit_key
                .trace_key()
                .project_prefix_coefficients_with_scratch_to(
                    &resources.workspace.scratch,
                    self.lookup_table.level_count().get(),
                    projected,
                    &mut resources.fft,
                    &mut self.trace_scratch,
                    resources.workspace.rotation.external_product(),
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
                    &mut resources.fft,
                    resources.workspace.rotation.external_product(),
                );
            }
        }
    }
}
