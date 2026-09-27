//! Packed one-hot selectors from one fused blind rotation.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_ntru::{FourierNgswCiphertext, NlevCiphertext};
use primus_tfhe::LweCiphertext;
pub use primus_tfhe_ntru::{OneHotBootstrapError, OneHotLookupTable};

use crate::{
    CircuitBootstrapKey, CircuitBootstrapParameters, Evaluator, ServerKey, TfheContext,
    TfheEvaluationError, blind_rotation::blind_rotate_lookup_table_to,
};

/// One-hot extension of CBS for classic binary/ternary LWE secrets.
///
/// Input uses unsigned Rounded encoding with t=2*M, M=2^tau, tau>=1.
/// All M selectors are materialized, including r=0. NLEV outputs are coefficient
/// polynomials under accumulator secret f at Q; NGSW outputs use this backend's
/// transform representation. Layout is `[selector][level][polynomial element]`,
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
        let n = pbs.context.parameters().poly_length();
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

    /// Returns the shared CBS bases and accumulator layouts.
    #[must_use]
    pub fn parameters(&self) -> &CircuitBootstrapParameters<T> {
        self.circuit_key.parameters()
    }

    /// Allocates M*L*N coefficients for all NLEV selectors. Reuse with [`Self::one_hot_nlev_to`].
    #[must_use]
    pub fn allocate_nlev_output(&self) -> Vec<T> {
        vec![T::ZERO; self.lookup_table.output_nlev_len()]
    }

    /// Allocates all transformed NGSW selectors: M*L*(N/2) elements.
    #[must_use]
    pub fn allocate_ngsw_output(&self) -> Vec<Complex64> {
        vec![Complex64::default(); self.lookup_table.output_nlev_len() / 2]
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
        self.evaluate(input, Some(output), None);
    }

    /// Writes transformed NGSW selectors only; retains no full NLEV output batch.
    /// Inherits [`Self::one_hot_to`]'s input, layout, noise and prewrite checks.
    pub fn one_hot_ngsw_to(&mut self, input: &LweCiphertext<T>, output: &mut [Complex64]) {
        self.evaluate(input, None, Some(output));
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
        self.evaluate(input, Some(nlev_output), Some(ngsw_output));
    }

    fn evaluate(
        &mut self,
        input: &LweCiphertext<T>,
        mut nlev_output: Option<&mut [T]>,
        mut ngsw_output: Option<&mut [Complex64]>,
    ) {
        let tfhe = self.pbs.context.parameters();
        let parameters = self.circuit_key.parameters();
        assert_eq!(
            input.dimension(),
            tfhe.external_lwe_dimension(),
            "one-hot input dimension mismatch"
        );
        if let Some(output) = &nlev_output {
            assert_eq!(
                output.len(),
                self.lookup_table.output_nlev_len(),
                "one-hot NLEV output length mismatch"
            );
        }
        if let Some(output) = &ngsw_output {
            assert_eq!(
                output.len(),
                self.lookup_table.output_nlev_len() / 2,
                "one-hot NGSW output length mismatch"
            );
        }
        blind_rotate_lookup_table_to(
            self.pbs.server_key,
            input,
            self.lookup_table.polynomial(),
            self.lookup_table.rotation_step(),
            &mut self.pbs.blind_rotation,
            tfhe,
            &mut self.pbs.fft,
        );
        let nlev_len = parameters.output_nlev_len();
        let ngsw_len = nlev_len / 2;
        for selector in 0..self.lookup_table.selector_count() {
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
                    self.lookup_table.level_count(),
                    projected,
                    &mut self.pbs.fft,
                    &mut self.trace_scratch,
                    self.pbs.blind_rotation.rotation.external_product(),
                );
            if let Some(output) = ngsw_output.as_deref_mut() {
                self.circuit_key.scheme_switch_key().apply_to(
                    &NlevCiphertext::new(&*projected),
                    &mut FourierNgswCiphertext::new(
                        &mut output[selector * ngsw_len..(selector + 1) * ngsw_len],
                    ),
                    &mut self.pbs.fft,
                    self.pbs.blind_rotation.rotation.external_product(),
                );
            }
        }
    }
}
