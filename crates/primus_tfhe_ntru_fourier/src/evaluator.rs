use primus_fft::{FftTable, TorusFftValue};
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, LweCiphertext, ProgrammableBootstrap,
    ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

use crate::{Lwe, LweReturnEvaluator, ServerKey, TfheContext, bootstrap::BlindRotationEngine};

/// Allocation-free online evaluator for Fourier NTRU programmable bootstrapping.
pub struct Evaluator<'a, T, Table, LM = primus_modulus::NativeModulus<T>>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    pub(crate) engine: BlindRotationEngine<'a, T, Table, LM>,
    pub(crate) lwe_return: LweReturnEvaluator<'a, T, LM>,
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
    ///
    /// The server key must have been generated with this context's FFT table
    /// instance. Parameter compatibility does not establish Fourier table identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table, LM>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Ok(Self::from_engine(BlindRotationEngine::try_new(
            context, server_key,
        )?))
    }

    /// Adds the client-return buffers to an already bound BR engine.
    #[must_use]
    pub(crate) fn from_engine(engine: BlindRotationEngine<'a, T, Table, LM>) -> Self {
        let lwe_return = LweReturnEvaluator::new(
            engine.server_key.key_switching_key(),
            engine.context.parameters().external_lwe().cipher_modulus(),
        );
        Self { engine, lwe_return }
    }

    /// Applies a compiled lookup table and allocates the returned ciphertext.
    ///
    /// Inherits [`ProgrammableBootstrap::apply_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics on an incompatible input dimension or LUT encoding/moduli/length,
    /// or if a streamed return batch is still active.
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
    /// or ciphertext dimensions, or if a streamed return batch is still active.
    pub fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        assert!(
            !self.lwe_return.is_batch_active(),
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
    /// Panics on an incompatible input dimension or LUT encoding/moduli/length,
    /// or if a streamed return batch is still active.
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
    /// or ciphertext dimensions. A wrong output count or an active streamed return
    /// batch is also rejected.
    pub fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        assert!(
            !self.lwe_return.is_batch_active(),
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
    pub(crate) fn return_accumulator_at_to(&mut self, index: usize, output: Lwe<&mut [T]>) {
        self.lwe_return
            .return_at_to(self.engine.workspace.current.as_view(), index, output);
    }

    /// Share Q→q across the interleaved prefix, keeping a scalar path for one output.
    fn return_accumulator_prefix_to(&mut self, outputs: &mut [LweCiphertext<T>]) {
        self.lwe_return
            .return_prefix_to(self.engine.workspace.current.as_view(), outputs);
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
    /// Creates an evaluator with reusable FFT and coefficient workspaces.
    /// The key must use this context's FFT table instance; see
    /// [`Evaluator::try_new`]'s correctness requirements.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table, LM>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }
}
