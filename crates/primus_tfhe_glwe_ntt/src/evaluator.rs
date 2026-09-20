use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingContext};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_glwe::PbsOrder;

use crate::{
    BootstrappingKey, NttGlweBlindRotationContext, NttGlweBootstrappingKey, ServerKey,
    SparseGlweBlindRotationContext, SparseGlweBootstrappingKey, TfheContext,
    error::TfheEvaluationError,
};

mod factorized;
pub use factorized::{FactorizedEvaluator, NttFactorizedLookupTable};

/// Reusable NTT workspace for programmable bootstrapping.
pub struct Evaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    pub(crate) context: &'a TfheContext<T, Table>,
    pub(crate) server_key: &'a ServerKey<T>,
    // try_new binds the key, parameters and table; this workspace stays private.
    blind_rotation: BlindRotation<'a, T>,
    // Only standalone BootstrapKeyswitch CBS omits this workspace.
    key_switching: Option<KeySwitchingWorkspace<T>>,
    // After BR: coefficient GLWE under the accumulator secret, in either order.
    main_glwe: GlweCiphertext<Vec<T>>,
}

struct KeySwitchingWorkspace<T: FheUint> {
    context: NttGlweKeySwitchingContext<T>,
    switched: GlweCiphertext<Vec<T>>,
    small_lwe: LweCiphertext<T>,
}

impl<T: FheUint> KeySwitchingWorkspace<T> {
    fn new(parameters: &crate::TfheParameters<T>) -> Self {
        Self {
            context: NttGlweKeySwitchingContext::new(
                parameters.glwe_key_switching().output().glwe_size(),
            ),
            switched: GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len()),
            small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension()),
        }
    }
}

// Pair each borrowed key with its own scratch once, avoiding mismatched variants
// and allocating only the workspace for the selected algorithm.
enum BlindRotation<'a, T: FheUint> {
    Classic {
        key: &'a NttGlweBootstrappingKey<T, primus_modulus::BarrettModulus<T>>,
        scratch: NttGlweBlindRotationContext<T>,
    },
    Sparse {
        key: &'a SparseGlweBootstrappingKey<T>,
        scratch: SparseGlweBlindRotationContext<T>,
    },
}

impl<T, Table> ProgrammableBootstrap<T> for Evaluator<'_, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    #[inline]
    fn apply_lookup_table_to(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut LweCiphertext<T>,
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
        input: &LweCiphertext<T>,
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
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::try_with_key_switching(context, server_key, true)
    }

    pub(crate) fn try_for_circuit_bootstrap(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        Self::try_with_key_switching(
            context,
            server_key,
            context.parameters().pbs_order() == PbsOrder::KeyswitchBootstrap,
        )
    }

    pub(crate) fn has_key_switching(&self) -> bool {
        self.key_switching.is_some()
    }

    pub(crate) fn complete_workspace(&mut self) {
        if self.key_switching.is_none() {
            self.key_switching = Some(KeySwitchingWorkspace::new(self.context.parameters()));
        }
    }

    fn try_with_key_switching(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
        with_key_switching: bool,
    ) -> Result<Self, TfheEvaluationError> {
        let parameters = context.parameters();
        if !server_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }

        Ok(Self {
            context,
            server_key,
            blind_rotation: match server_key.bootstrapping_key() {
                BootstrappingKey::Classic(key) => BlindRotation::Classic {
                    key,
                    scratch: NttGlweBlindRotationContext::new(key),
                },
                BootstrappingKey::Sparse(key) => BlindRotation::Sparse {
                    key,
                    scratch: SparseGlweBlindRotationContext::new(key),
                },
            },
            key_switching: with_key_switching.then(|| KeySwitchingWorkspace::new(parameters)),
            main_glwe: GlweCiphertext::zero(parameters.accumulator_glwe().glwe_len()),
        })
    }

    pub(crate) fn with_external_product<R>(
        &mut self,
        size: primus_lattice::GadgetSize,
        operation: impl FnOnce(&mut primus_lattice::context::NttGlweExternalProductContext<T>) -> R,
    ) -> R {
        match &mut self.blind_rotation {
            BlindRotation::Classic { scratch, .. } => {
                scratch.with_external_product(size, operation)
            }
            BlindRotation::Sparse { scratch, .. } => scratch.with_external_product(size, operation),
        }
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
        input: &LweCiphertext<T>,
        lookup_table: &LookupTable<T>,
    ) -> LweCiphertext<T> {
        let mut output = LweCiphertext::zero(self.context.parameters().external_lwe_dimension());
        self.apply_lookup_table_to(input, lookup_table, &mut output);
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
        input: &LweCiphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut LweCiphertext<T>,
    ) {
        let parameters = self.context.parameters();
        assert!(
            lookup_table.is_compatible(
                parameters.accumulator_glwe().poly_length(),
                parameters.plain_modulus_value(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.accumulator_glwe().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            expected_dimension,
            "PBS input dimension mismatch"
        );
        assert_eq!(
            output.dimension(),
            expected_dimension,
            "PBS output dimension mismatch"
        );

        let glwe = parameters.accumulator_glwe();
        self.blind_rotate(input, lookup_table.polynomial(), 1);
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                let switched = self.keyswitch_accumulator();
                switched.extract_compact_lwe_to(output, glwe.poly_length(), glwe.cipher_modulus());
            }
            PbsOrder::KeyswitchBootstrap => {
                self.main_glwe
                    .extract_lwe_to(output, glwe.poly_length(), glwe.cipher_modulus());
            }
        }
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
        input: &LweCiphertext<T>,
        lookup_table: &InterleavedLookupTable<T>,
    ) -> Vec<LweCiphertext<T>> {
        let dimension = self.context.parameters().external_lwe_dimension();
        let mut outputs = (0..lookup_table.output_count())
            .map(|_| LweCiphertext::zero(dimension))
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
        input: &LweCiphertext<T>,
        lookup_table: &InterleavedLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let parameters = self.context.parameters();
        assert!(
            lookup_table.is_compatible(
                parameters.accumulator_glwe().poly_length(),
                parameters.plain_modulus_value(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.accumulator_glwe().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            expected_dimension,
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
                .all(|output| output.dimension() == expected_dimension),
            "PBSManyLUT output ciphertext dimension mismatch"
        );

        let glwe = parameters.accumulator_glwe();
        self.blind_rotate(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                let switched = self.keyswitch_accumulator();
                for (index, output) in outputs.iter_mut().enumerate() {
                    switched.extract_compact_lwe_at_to(
                        index,
                        output,
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
            }
            PbsOrder::KeyswitchBootstrap => {
                for (index, output) in outputs.iter_mut().enumerate() {
                    self.main_glwe.extract_lwe_at_to(
                        index,
                        output,
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
            }
        }
    }

    /// Prepares the small-LWE input for the selected order, then writes the BR
    /// result to `main_glwe` in coefficient form under the accumulator secret.
    /// The caller checked input/LUT compatibility; `rotation_step` is the LUT's
    /// padded output count (one for ordinary PBS). No output key switch occurs.
    #[inline]
    pub(crate) fn blind_rotate(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) -> &GlweCiphertext<Vec<T>> {
        let parameters = self.context.parameters();
        let small_lwe = match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => input,
            PbsOrder::KeyswitchBootstrap => {
                let ks = self
                    .key_switching
                    .as_mut()
                    .expect("input KS workspace is constructed for KeyswitchBootstrap");
                let glwe = parameters.accumulator_glwe();
                input.inverse_extract_glwe_to(
                    &mut self.main_glwe,
                    glwe.poly_length(),
                    glwe.cipher_modulus(),
                );
                self.server_key.glwe_key_switching_key().key_switch_to(
                    &self.main_glwe,
                    &mut ks.switched,
                    glwe.cipher_modulus(),
                    self.context.table(),
                    &mut ks.context,
                );
                ks.switched.extract_compact_lwe_to(
                    &mut ks.small_lwe,
                    glwe.poly_length(),
                    glwe.cipher_modulus(),
                );
                &ks.small_lwe
            }
        };
        match &mut self.blind_rotation {
            BlindRotation::Classic { key, scratch } => key
                .ntt_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table,
                    rotation_step,
                    &mut self.main_glwe,
                    parameters.accumulator_glwe().cipher_modulus(),
                    self.context.table(),
                    scratch,
                ),
            BlindRotation::Sparse { key, scratch } => key
                .ntt_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table,
                    rotation_step,
                    &mut self.main_glwe,
                    self.context.table(),
                    scratch,
                ),
        }
        &self.main_glwe
    }

    /// Switches `main_glwe` from the accumulator secret to the padded small
    /// secret in coefficient-domain `switched`, ready for compact extraction.
    /// Ordinary/interleaved PBS calls this only for BootstrapKeyswitch; the
    /// accumulator remains available for consumers needing its original secret.
    #[inline]
    fn keyswitch_accumulator(&mut self) -> &GlweCiphertext<Vec<T>> {
        let ks = self
            .key_switching
            .as_mut()
            .expect("ordinary PBS owns key-switching workspace");
        let glwe = self.context.parameters().accumulator_glwe();
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut ks.switched,
            glwe.cipher_modulus(),
            self.context.table(),
            &mut ks.context,
        );
        &ks.switched
    }
}
