//! Default one-hot workflow with one resource owner for every selector mode.

use primus_fft::{Complex64, FftTable, TorusFftValue};
use primus_ntru::{FourierNgswCiphertext, NtruCiphertext};

use crate::{
    BootstrapResources, CbsGadgetParameters, CircuitBootstrapServerKey, FourierNgswSelectors, Lwe,
    NlevSelectors, OneHotBootstrapError, OneHotCircuitBootstrapEvaluator, OneHotLookupTable,
    TfheContext,
};

/// One-hot CBS state paired with its reusable input/BR/projection resources.
///
/// Created by [`TfheContext::one_hot_evaluator`]. Owns exactly the buffers used
/// by selector generation, without return scratch, key copies or a second table.
/// Full batches include r=0; compact batches omit only that branch. Coefficient
/// NLEV and transformed NGSW remain distinct representations; inherit
/// [`OneHotCircuitBootstrapEvaluator`]'s encoding, secret, transform and noise contracts.
pub struct OneHotEvaluator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    operation: OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
    resources: BootstrapResources<'a, T, Table, LM>,
}

impl<'a, T, Table, LM> OneHotEvaluator<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Inherits [`OneHotCircuitBootstrapEvaluator::lookup_table`]'s layout contract.
    #[must_use]
    pub fn lookup_table(&self) -> &OneHotLookupTable<T> {
        self.operation.lookup_table()
    }

    /// Inherits [`OneHotCircuitBootstrapEvaluator::parameters`]'s layout contract.
    #[must_use]
    pub fn parameters(&self) -> &'a CbsGadgetParameters<T> {
        self.operation.parameters()
    }

    /// Inherits [`OneHotCircuitBootstrapEvaluator::ngsw_selector_len`]'s layout contract.
    #[must_use]
    pub fn ngsw_selector_len(&self) -> usize {
        self.operation.ngsw_selector_len()
    }

    /// Inherits [`OneHotCircuitBootstrapEvaluator::ngsw_batch_len`]'s layout contract.
    #[must_use]
    pub fn ngsw_batch_len(&self) -> usize {
        self.operation.ngsw_batch_len()
    }

    /// Inherits [`OneHotCircuitBootstrapEvaluator::allocate_nlev_output`]'s layout contract.
    #[must_use]
    pub fn allocate_nlev_output(&self) -> Vec<T> {
        self.operation.allocate_nlev_output()
    }

    /// Inherits [`OneHotCircuitBootstrapEvaluator::allocate_ngsw_output`]'s layout contract.
    #[must_use]
    pub fn allocate_ngsw_output(&self) -> Vec<Complex64> {
        self.operation.allocate_ngsw_output()
    }

    /// Inherits [`OneHotCircuitBootstrapEvaluator::allocate_nonzero_ngsw_output`]'s layout contract.
    #[must_use]
    pub fn allocate_nonzero_ngsw_output(&self) -> Vec<Complex64> {
        self.operation.allocate_nonzero_ngsw_output()
    }

    /// Borrows selector controls; inherits [`OneHotCircuitBootstrapEvaluator::nlev_selectors`]'s
    /// exact shape, branch-index and representation contracts.
    #[must_use]
    pub fn nlev_selectors<'b>(&self, output: &'b [T]) -> NlevSelectors<'b, T> {
        self.operation.nlev_selectors(output)
    }

    /// Borrows selector controls; inherits [`OneHotCircuitBootstrapEvaluator::ngsw_selectors`]'s
    /// exact shape, branch-index and representation contracts.
    #[must_use]
    pub fn ngsw_selectors<'b>(&self, output: &'b [Complex64]) -> FourierNgswSelectors<'b> {
        self.operation.ngsw_selectors(output)
    }

    /// Borrows selector controls; inherits [`OneHotCircuitBootstrapEvaluator::nonzero_ngsw_selectors`]'s
    /// exact shape, branch-index and representation contracts.
    #[must_use]
    pub fn nonzero_ngsw_selectors<'b>(&self, output: &'b [Complex64]) -> FourierNgswSelectors<'b> {
        self.operation.nonzero_ngsw_selectors(output)
    }

    /// Writes selectors without allocating. Inherits
    /// [`OneHotCircuitBootstrapEvaluator::one_hot_nlev_to`]'s input, output and noise contracts.
    pub fn one_hot_nlev_to(&mut self, input: Lwe<&[T]>, output: &mut [T]) {
        self.operation
            .one_hot_nlev_to(input, output, &mut self.resources);
    }

    /// Writes selectors without allocating. Inherits
    /// [`OneHotCircuitBootstrapEvaluator::one_hot_ngsw_to`]'s input, output and noise contracts.
    pub fn one_hot_ngsw_to(&mut self, input: Lwe<&[T]>, output: &mut [Complex64]) {
        self.operation
            .one_hot_ngsw_to(input, output, &mut self.resources);
    }

    /// Writes selectors without allocating. Inherits
    /// [`OneHotCircuitBootstrapEvaluator::one_hot_nonzero_ngsw_to`]'s input, output and noise contracts.
    pub fn one_hot_nonzero_ngsw_to(&mut self, input: Lwe<&[T]>, output: &mut [Complex64]) {
        self.operation
            .one_hot_nonzero_ngsw_to(input, output, &mut self.resources);
    }

    /// Writes both representations from one BR and shared projections.
    /// Inherits [`OneHotCircuitBootstrapEvaluator::one_hot_to`]'s shape,
    /// branch-index, encoding and noise contracts.
    pub fn one_hot_to(
        &mut self,
        input: Lwe<&[T]>,
        nlev_output: &mut [T],
        ngsw_output: &mut [Complex64],
    ) {
        self.operation
            .one_hot_to(input, nlev_output, ngsw_output, &mut self.resources);
    }

    /// Writes both representations from one BR and shared projections.
    /// Inherits [`OneHotCircuitBootstrapEvaluator::one_hot_nlev_and_nonzero_ngsw_to`]'s shape,
    /// branch-index, encoding and noise contracts.
    pub fn one_hot_nlev_and_nonzero_ngsw_to(
        &mut self,
        input: Lwe<&[T]>,
        nlev_output: &mut [T],
        ngsw_output: &mut [Complex64],
    ) {
        self.operation.one_hot_nlev_and_nonzero_ngsw_to(
            input,
            nlev_output,
            ngsw_output,
            &mut self.resources,
        );
    }

    /// Selects a coefficient-ring candidate with a one-hot bit control.
    /// Inherits [`OneHotCircuitBootstrapEvaluator::cmux_to`]'s layout, secret,
    /// representation, candidate encoding and noise contracts.
    pub fn cmux_to(
        &mut self,
        control: FourierNgswCiphertext<&[Complex64]>,
        lhs: NtruCiphertext<&[T]>,
        rhs: NtruCiphertext<&[T]>,
        mut output: NtruCiphertext<&mut [T]>,
    ) {
        self.operation
            .cmux_to(&control, &lhs, &rhs, &mut output, &mut self.resources);
    }

    /// Multiplies a ring ciphertext by a selector control.
    /// Inherits [`OneHotCircuitBootstrapEvaluator::external_product_to`]'s contracts.
    pub fn external_product_to(
        &mut self,
        control: FourierNgswCiphertext<&[Complex64]>,
        input: NtruCiphertext<&[T]>,
        mut output: NtruCiphertext<&mut [T]>,
    ) {
        self.operation
            .external_product_to(&control, &input, &mut output, &mut self.resources);
    }

    /// Moves out prepared state and resources for serial composition with other
    /// operations, including the advanced sparse-pair projection interface.
    /// No buffers are copied or allocated.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        OneHotCircuitBootstrapEvaluator<'a, T, Table, LM>,
        BootstrapResources<'a, T, Table, LM>,
    ) {
        (self.operation, self.resources)
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares configured one-hot CBS with one owned resource set.
    /// Uses the retained input encoding/gadgets, without an ordinary return stage.
    /// Shape and selector-capacity errors precede online evaluation.
    ///
    /// # Correctness
    /// The complete server key must pair the actual external/accumulator secrets
    /// in this Context's transform representation; metadata checks cannot establish
    /// identities or a noise budget. Inherits
    /// [`OneHotCircuitBootstrapEvaluator::one_hot_to`]'s numerical requirements.
    pub fn one_hot_evaluator<'a>(
        &'a self,
        server_key: &'a CircuitBootstrapServerKey<T>,
    ) -> Result<OneHotEvaluator<'a, T, Table, LM>, OneHotBootstrapError> {
        let resources = server_key.bootstrap_resources(self)?;
        let operation =
            self.one_hot_evaluator_with_resources(&resources, server_key.circuit_bootstrap_key())?;
        Ok(OneHotEvaluator {
            operation,
            resources,
        })
    }
}
