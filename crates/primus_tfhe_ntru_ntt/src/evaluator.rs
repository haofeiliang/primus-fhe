use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, LweCiphertext, ProgrammableBootstrap,
    ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

use crate::{
    BlindRotationKey, Lwe, LweReturnBatchWorkspace, LweReturnEvaluator, ServerKey, TfheContext,
    bootstrap::BlindRotationEngine,
};

/// Allocation-free online evaluator for exact NTT NTRU programmable bootstrapping.
pub struct Evaluator<'a, T, Table, LM = primus_modulus::BarrettModulus<T>>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) engine: BlindRotationEngine<'a, T, Table, LM>,
    pub(crate) lwe_return: LweReturnEvaluator<'a, T, LM>,
    scalar_return: primus_ntru::NtruLweKeySwitchingWorkspace<T>,
    pub(crate) batch_return: LweReturnBatchWorkspace<T>,
}

impl<'a, T, Table, LM> Evaluator<'a, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates reusable evaluation state after checking the server key once.
    ///
    /// # Correctness
    /// The server key must use the NTT representation of `context.table()`.
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
        let engine = BlindRotationEngine::try_new(context, blind_rotation_key)?;
        Ok(Self::from_engine(engine, return_key))
    }

    /// Adds client-return buffers after the owning boundary checked return compatibility.
    #[must_use]
    pub(crate) fn from_engine(
        engine: BlindRotationEngine<'a, T, Table, LM>,
        return_key: &'a primus_ntru::NtruLweKeySwitchingKey<T>,
    ) -> Self {
        let lwe_return = LweReturnEvaluator::new(
            return_key,
            engine.context.parameters().external_lwe().cipher_modulus(),
        );
        let scalar_return = lwe_return.new_scalar_workspace();
        let batch_return = lwe_return.new_batch_workspace();
        Self {
            engine,
            lwe_return,
            scalar_return,
            batch_return,
        }
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
        let dimension = self.engine.context.parameters().external_lwe_dimension();
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
        assert!(
            !self.batch_return.is_batch_active(),
            "finish or discard the pending NTRU return batch first"
        );
        let parameters = self.engine.context.parameters();
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

        self.engine
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
        let dimension = self.engine.context.parameters().external_lwe_dimension();
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
        assert!(
            !self.batch_return.is_batch_active(),
            "finish or discard the pending NTRU return batch first"
        );
        let parameters = self.engine.context.parameters();
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

        self.engine.blind_rotate(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        self.return_accumulator_prefix_to(outputs);
    }

    /// CBS consumes `current` directly; ordinary PBS returns its phase coefficient.
    fn return_accumulator_at_to(&mut self, index: usize, output: Lwe<&mut [T]>) {
        self.lwe_return.return_at_to(
            self.engine.workspace.current.as_view(),
            index,
            output,
            &mut self.scalar_return,
        );
    }

    /// Share Q→q across the interleaved prefix. The batch kernel also handles
    /// singleton outputs directly, without a tile copy.
    fn return_accumulator_prefix_to(&mut self, outputs: &mut [LweCiphertext<T>]) {
        self.lwe_return.return_prefix_to(
            self.engine.workspace.current.as_view(),
            outputs,
            &mut self.batch_return,
        );
    }
}

impl<T, Table, LM> ProgrammableBootstrap<T> for Evaluator<'_, T, Table, LM>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
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
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
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
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
    LM: primus_reduce::RingContext<T>,
{
    /// Creates an evaluator with reusable NTT and coefficient workspaces.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table, LM>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }
}
