use primus_fft::{FftTable, TorusFftValue};
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, LweCiphertext, ProgrammableBootstrap,
    ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

use crate::{
    BlindRotationKey, Lwe, LweReturnBatchWorkspace, LweReturnEvaluator, ServerKey, TfheContext,
    bootstrap::BootstrapResources,
};

/// Allocation-free online evaluator for Fourier NTRU programmable bootstrapping.
/// Owns common BR/EP and scalar/batch return resources. CBS/one-hot can borrow
/// the former; factorized MVB borrows the evaluator for a complete request.
/// Scalar PBS uses independent return scratch. A new interleaved/MVB request
/// discards pending batch samples from an unwind.
pub struct Evaluator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) resources: BootstrapResources<'a, T, Table, LM>,
    pub(crate) lwe_return: LweReturnEvaluator<'a, T, LM>,
    scalar_return: primus_ntru::NtruLweKeySwitchingWorkspace<T>,
    pub(crate) batch_return: LweReturnBatchWorkspace<T>,
}

impl<'a, T, Table, LM> Evaluator<'a, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates reusable evaluation state after checking the server key once.
    ///
    /// # Correctness
    /// The server key must use this context's FFT table instance.
    /// Layout and basis checks do not establish transform or secret identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::try_from_parts(
            context,
            server_key.blind_rotation_key(),
            server_key.key_switching_key(),
        )
    }

    /// Binds independent BR and Q→q, f→s return material before allocating scratch.
    /// The keys must share actual secrets and this context's transform representation;
    /// layout, distribution, basis and modulus checks do not establish identity.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table, LM>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        context.parameters().check_lwe_return_key(return_key)?;
        let resources = BootstrapResources::try_new(context, blind_rotation_key)?;
        Ok(Self::from_resources(resources, return_key))
    }

    /// Adds client-return buffers after the owning boundary checked return compatibility.
    #[must_use]
    fn from_resources(
        resources: BootstrapResources<'a, T, Table, LM>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Self {
        let lwe_return = LweReturnEvaluator::new(
            return_key,
            resources
                .context
                .parameters()
                .external_lwe()
                .cipher_modulus(),
        );
        let scalar_return = lwe_return.new_scalar_workspace();
        let batch_return = lwe_return.new_batch_workspace();
        Self {
            resources,
            lwe_return,
            scalar_return,
            batch_return,
        }
    }

    /// Borrows the shared BR/EP resources to prepare an operation's own buffers.
    #[must_use]
    pub fn bootstrap_resources(&self) -> &BootstrapResources<'a, T, Table, LM> {
        &self.resources
    }

    /// Lends common resources for CBS/one-hot or table products. Return buffers
    /// remain owned here, so ordinary PBS can resume after the short borrow ends.
    ///
    /// # Correctness
    /// Preserve the context and BR key binding: the retained return material and
    /// scratch were prepared for it. This borrow is not an evaluator-rebinding API.
    #[must_use]
    pub fn bootstrap_resources_mut(&mut self) -> &mut BootstrapResources<'a, T, Table, LM> {
        &mut self.resources
    }

    /// Adds ordinary return buffers to independently prepared BR resources.
    /// The return key must share the resources' accumulator secret and intended
    /// external secret; compatibility checks do not establish secret identity.
    pub fn try_from_resources(
        resources: BootstrapResources<'a, T, Table, LM>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        resources
            .context
            .parameters()
            .check_lwe_return_key(return_key)?;
        Ok(Self::from_resources(resources, return_key))
    }

    /// Changes compatible return material without reallocating scratch. Success
    /// discards pending samples; incompatible material leaves this evaluator intact.
    /// The new key must share the BR accumulator secret and intended output secret.
    pub fn try_rebind_return_key(
        &mut self,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Result<(), TfheEvaluationError> {
        let parameters = self.resources.context.parameters();
        parameters.check_lwe_return_key(return_key)?;
        self.lwe_return =
            LweReturnEvaluator::new(return_key, parameters.external_lwe().cipher_modulus());
        self.batch_return.discard_batch();
        Ok(())
    }

    /// Applies a compiled lookup table and allocates the returned ciphertext.
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics on an incompatible input dimension or LUT encoding/moduli/length.
    #[must_use]
    pub fn apply_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
    ) -> LweCiphertext<T> {
        let dimension = self.resources.context.parameters().external_lwe_dimension();
        let mut output = LweCiphertext::zero(dimension.get());
        self.apply_lookup_table_to(input, lookup_table, output.as_mut_view());
        output
    }

    /// Applies a compiled lookup table into an existing LWE allocation.
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes on incompatible LUT encoding/moduli/length
    /// or ciphertext dimensions.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        let parameters = self.resources.context.parameters();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.poly_length(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            lwe_dimension.get(),
            "PBS input dimension mismatch"
        );
        assert_eq!(
            output.dimension(),
            lwe_dimension.get(),
            "PBS output dimension mismatch"
        );

        self.resources
            .blind_rotate(input, lookup_table.polynomial(), 1);
        self.return_accumulator_at_to(0, output);
    }

    /// Applies all interleaved lookup tables and allocates one ciphertext per output.
    ///
    /// Shares one blind rotation and Q→q conversion, then batches LWE key switches.
    ///
    /// Inherits [`ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics on an incompatible input dimension or LUT encoding/moduli/length.
    #[must_use]
    pub fn apply_interleaved_lookup_table(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
    ) -> Vec<LweCiphertext<T>> {
        let dimension = self.resources.context.parameters().external_lwe_dimension();
        let mut outputs = (0..lookup_table.output_count())
            .map(|_| LweCiphertext::zero(dimension.get()))
            .collect::<Vec<_>>();
        self.apply_interleaved_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Applies all interleaved tables into reusable output allocations.
    ///
    /// Shares one blind rotation and Q→q conversion, then batches LWE key switches.
    ///
    /// Inherits [`ProgrammableBootstrapInterleaved::apply_interleaved_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes on incompatible LUT encoding/moduli/length
    /// or ciphertext dimensions. A wrong output count is also rejected.
    pub fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let parameters = self.resources.context.parameters();
        assert!(
            lookup_table.is_compatible_with_ciphertext_domain(
                parameters.poly_length(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            lwe_dimension.get(),
            "PBS input dimension mismatch"
        );
        assert_eq!(
            outputs.len(),
            lookup_table.output_count(),
            "PBSManyLUT output slice length mismatch"
        );
        assert!(
            outputs
                .iter()
                .all(|output| output.dimension() == lwe_dimension.get()),
            "PBSManyLUT output ciphertext dimension mismatch"
        );

        self.batch_return.discard_batch();
        self.resources.blind_rotate(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        self.return_accumulator_prefix_to(outputs);
    }

    /// CBS consumes `current` directly; ordinary PBS returns its phase coefficient.
    fn return_accumulator_at_to(&mut self, index: usize, output: Lwe<&mut [T]>) {
        self.lwe_return.return_at_to(
            self.resources.workspace.current.as_view(),
            index,
            output,
            &mut self.scalar_return,
        );
    }

    /// Share Q→q across the interleaved prefix. The batch kernel also handles
    /// singleton outputs directly, without a tile copy.
    fn return_accumulator_prefix_to(&mut self, outputs: &mut [LweCiphertext<T>]) {
        self.lwe_return.return_prefix_to(
            self.resources.workspace.current.as_view(),
            outputs,
            &mut self.batch_return,
        );
    }
}

impl<T, Table, LM> ProgrammableBootstrap<T> for Evaluator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    #[inline]
    fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        Self::apply_lookup_table_to(self, input, lookup_table, output);
    }
}

impl<T, Table, LM> ProgrammableBootstrapInterleaved<T> for Evaluator<'_, T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    #[inline]
    fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        Self::apply_interleaved_lookup_table_to(self, input, lookup_table, outputs);
    }
}

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates an evaluator with reusable Fourier and coefficient workspaces.
    /// Inherits [`Evaluator::try_new`]'s key and FFT table requirements.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table, LM>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }
}
