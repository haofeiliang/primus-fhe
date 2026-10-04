use primus_glwe::NttGlweKeySwitchingKey;
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::MonomialNttTable;
use primus_reduce::Modulus;
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_glwe::PbsOrder;

use crate::{
    BlindRotationKey, Lwe, ServerKey, TfheContext,
    bootstrap::{BootstrapResources, KeySwitchingWorkspace},
    error::TfheEvaluationError,
};

/// Reusable NTT programmable bootstrap with common resources and a complete return stage.
/// BR→KS owns output KS; KS→BR uses the common input KS and extracts directly.
/// CBS borrows common resources and MVB borrows this evaluator for each request.
pub struct Evaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) resources: BootstrapResources<'a, T, Table>,
    lwe_return: LweReturn<'a, T>,
}

/// The result stage is complete and selected once for the bound PBS order.
enum LweReturn<'a, T: FheUint> {
    Keyswitch(KeySwitchingWorkspace<'a, T>),
    Extract,
}

impl<T, Table> ProgrammableBootstrap<T> for Evaluator<'_, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    #[inline]
    fn apply_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &LookupTable<T>,
        output: Lwe<&mut [T]>,
    ) {
        Evaluator::apply_lookup_table_to(self, input, lookup_table, output)
    }
}

impl<T, Table> ProgrammableBootstrapInterleaved<T> for Evaluator<'_, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    #[inline]
    fn apply_interleaved_lookup_table_to(
        &mut self,
        input: Lwe<&[T]>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        Evaluator::apply_interleaved_lookup_table_to(self, input, lookup_table, outputs)
    }
}

impl<'a, T, Table> Evaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates an evaluator after checking the server-key layout.
    ///
    /// # Correctness
    ///
    /// The server key must use the NTT representation of `context.table()`:
    /// primitive root, ordering and normalization must agree. Layout and modulus
    /// checks do not establish transform or secret identity; see
    /// [`primus_ntt::NttTable::new`].
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::try_from_parts(
            context,
            server_key.blind_rotation_key(),
            server_key.glwe_key_switching_key(),
        )
    }

    /// Binds independent BR and ring KS material for either PBS order.
    /// Checks layouts, input distribution and decomposition bases/moduli once.
    ///
    /// # Correctness
    /// Materials must use the same paired small/accumulator secrets and context
    /// transform representation; parameter checks cannot establish their identity.
    /// Inherits [`Self::try_new`]'s transform requirements.
    pub fn try_from_parts(
        context: &'a TfheContext<T, Table>,
        blind_rotation_key: &'a BlindRotationKey<T>,
        key_switching_key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let resources =
            BootstrapResources::try_new(context, blind_rotation_key, Some(key_switching_key))?;
        Ok(Self::from_resources(resources, key_switching_key))
    }

    /// Complete the output stage with an already checked KS key;
    /// the resources already own input KS for KS→BR.
    #[must_use]
    fn from_resources(
        mut resources: BootstrapResources<'a, T, Table>,
        key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Self {
        resources.rebind_input_key_switching_key(key);
        let parameters = resources.context.parameters();
        let lwe_return = match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                LweReturn::Keyswitch(KeySwitchingWorkspace::new(parameters, key))
            }
            PbsOrder::KeyswitchBootstrap => LweReturn::Extract,
        };
        Self {
            resources,
            lwe_return,
        }
    }

    /// Borrows common resources to prepare CBS operation state.
    #[must_use]
    pub fn bootstrap_resources(&self) -> &BootstrapResources<'a, T, Table> {
        &self.resources
    }

    /// Lends common input/BR/EP resources while retaining the ordinary return stage.
    ///
    /// # Correctness
    /// Preserve the context and paired-secret binding: retained return material
    /// and buffers were prepared for it. This borrow does not rebind the evaluator.
    #[must_use]
    pub fn bootstrap_resources_mut(&mut self) -> &mut BootstrapResources<'a, T, Table> {
        &mut self.resources
    }

    /// Completes ordinary PBS from standalone resources and compatible ring KS material.
    /// BR→KS allocates output KS; KS→BR rebinds the existing input KS without allocation.
    ///
    /// # Correctness
    /// The KS key must use the resources' paired secrets and NTT representation.
    pub fn try_from_resources(
        resources: BootstrapResources<'a, T, Table>,
        key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        crate::key::check_glwe_key_switching_key(resources.context.parameters(), key)?;
        Ok(Self::from_resources(resources, key))
    }

    /// Rebinds compatible KS material without reallocating either order's active stage.
    /// Failure leaves the previous binding intact.
    ///
    /// # Correctness
    /// The replacement must use the original paired secrets and NTT representation.
    pub fn try_rebind_key_switching_key(
        &mut self,
        key: &'a NttGlweKeySwitchingKey<T>,
    ) -> Result<(), TfheEvaluationError> {
        crate::key::check_glwe_key_switching_key(self.resources.context.parameters(), key)?;
        self.resources.rebind_input_key_switching_key(key);
        if let LweReturn::Keyswitch(workspace) = &mut self.lwe_return {
            workspace.key = key;
        }
        Ok(())
    }

    /// Applies a compiled lookup table and returns a refreshed ciphertext in
    /// the external LWE dimension selected by the PBS order.
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

    /// Applies a compiled lookup table into an existing ciphertext allocation.
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
                parameters.blind_rotation_ggsw().poly_length(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.cipher_modulus().explicit_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            expected_dimension.get(),
            "PBS input dimension mismatch"
        );
        assert_eq!(
            output.dimension(),
            expected_dimension.get(),
            "PBS output dimension mismatch"
        );

        self.resources
            .blind_rotate(input, lookup_table.polynomial(), 1);
        self.return_accumulator_to(core::iter::once(output));
    }

    /// Applies all interleaved tables and allocates one ciphertext per output.
    ///
    /// Shares one blind rotation and one ring key switch.
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

    /// Applies all interleaved tables into reusable ciphertext allocations.
    ///
    /// Shares one blind rotation and one ring key switch.
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
                parameters.blind_rotation_ggsw().poly_length(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.cipher_modulus().explicit_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            expected_dimension.get(),
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
                .all(|output| output.dimension() == expected_dimension.get()),
            "PBSManyLUT output ciphertext dimension mismatch"
        );

        self.resources.blind_rotate(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        self.return_accumulator_to(outputs.iter_mut().map(Lwe::as_mut_view));
    }

    /// Return a validated phase prefix. BR→KS switches the ring once before compact
    /// extraction; KS→BR directly extracts under the accumulator LWE secret.
    /// Iterating views lets the single-output path share extraction without an
    /// owned ciphertext wrapper or an allocated batch of view descriptors.
    #[inline]
    pub(crate) fn return_accumulator_to<'out>(
        &mut self,
        outputs: impl Iterator<Item = Lwe<&'out mut [T]>>,
    ) {
        let resources = &mut self.resources;
        let glwe = resources.context.parameters().blind_rotation_ggsw();
        match &mut self.lwe_return {
            LweReturn::Keyswitch(ks) => {
                ks.key.key_switch_to(
                    &resources.accumulator,
                    &mut ks.switched,
                    glwe.cipher_modulus(),
                    resources.context.table(),
                    &mut ks.scratch,
                );
                for (index, mut output) in outputs.enumerate() {
                    ks.switched.extract_compact_lwe_at_to(
                        index,
                        &mut output,
                        glwe.poly_length().get(),
                        glwe.cipher_modulus(),
                    );
                }
            }
            LweReturn::Extract => {
                for (index, mut output) in outputs.enumerate() {
                    resources.accumulator.extract_lwe_at_to(
                        index,
                        &mut output,
                        glwe.poly_length().get(),
                        glwe.cipher_modulus(),
                    );
                }
            }
        }
    }
}

impl<T, Table> TfheContext<T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates a programmable-bootstrap evaluator with reusable NTT workspace.
    pub fn evaluator<'a>(
        &'a self,
        server_key: &'a ServerKey<T>,
    ) -> Result<Evaluator<'a, T, Table>, TfheEvaluationError> {
        Evaluator::try_new(self, server_key)
    }
}
