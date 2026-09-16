use primus_glwe::{GlweCiphertext, NttGlweKeySwitchingContext};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::NttTable;
use primus_poly::Polynomial;
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_glwe::GlwePbsOrder as PbsOrder;

use crate::{NttGlweBlindRotationContext, ServerKey, TfheContext, error::TfheEvaluationError};

/// Reusable NTT workspace for programmable bootstrapping.
pub struct Evaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey<T>,
    // try_new binds the key, parameters and table; this workspace stays private.
    blind_rotation: NttGlweBlindRotationContext<T>,
    key_switching: NttGlweKeySwitchingContext<T>,
    main_glwe: GlweCiphertext<Vec<T>>,
    switched: GlweCiphertext<Vec<T>>,
    small_lwe: LweCiphertext<T>,
}

impl<T, Table> ProgrammableBootstrap<T> for Evaluator<'_, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
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
    Table: NttTable<ValueT = T>,
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
    Table: NttTable<ValueT = T>,
{
    /// Creates an evaluator after checking the server-key layout.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        let parameters = context.parameters();
        if !server_key.is_compatible(parameters) {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }

        let key_switching_context =
            NttGlweKeySwitchingContext::new(parameters.glwe_key_switching().output().glwe_size());
        Ok(Self {
            context,
            server_key,
            blind_rotation: NttGlweBlindRotationContext::new(parameters.bootstrapping().size()),
            key_switching: key_switching_context,
            main_glwe: GlweCiphertext::zero(parameters.glwe().glwe_len()),
            switched: GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len()),
            small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension()),
        })
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
        let mut output = LweCiphertext::zero(self.context.parameters().ciphertext_lwe_dimension());
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
                parameters.glwe().poly_length(),
                parameters.plain_modulus_value(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.glwe().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.ciphertext_lwe_dimension();
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

        let glwe = parameters.glwe();
        let result = self.evaluate_to_glwe(input, lookup_table.polynomial(), 1);
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                result.extract_compact_lwe_to(output, glwe.poly_length(), glwe.cipher_modulus());
            }
            PbsOrder::KeyswitchBootstrap => {
                result.extract_lwe_to(output, glwe.poly_length(), glwe.cipher_modulus());
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
        let dimension = self.context.parameters().ciphertext_lwe_dimension();
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
                parameters.glwe().poly_length(),
                parameters.plain_modulus_value(),
                parameters.small_lwe().cipher_modulus_value(),
                parameters.glwe().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let expected_dimension = parameters.ciphertext_lwe_dimension();
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

        let glwe = parameters.glwe();
        let result = self.evaluate_to_glwe(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                for (index, output) in outputs.iter_mut().enumerate() {
                    result.extract_compact_lwe_at_to(
                        index,
                        output,
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
            }
            PbsOrder::KeyswitchBootstrap => {
                for (index, output) in outputs.iter_mut().enumerate() {
                    result.extract_lwe_at_to(
                        index,
                        output,
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
            }
        }
    }

    /// Returns switched ring storage for BootstrapKeyswitch, main ring storage otherwise.
    /// The caller checked input/LUT compatibility. The rotation step equals
    /// the compiled LUT padded output count.
    /// A rotation step of one gives ordinary modulus switching.
    #[inline]
    fn evaluate_to_glwe(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) -> &GlweCiphertext<Vec<T>> {
        let parameters = self.context.parameters();
        let small_lwe = match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => input,
            PbsOrder::KeyswitchBootstrap => {
                prepare_small_lwe(
                    self.context,
                    self.server_key,
                    input,
                    &mut self.main_glwe,
                    &mut self.switched,
                    &mut self.small_lwe,
                    &mut self.key_switching,
                );
                &self.small_lwe
            }
        };
        self.server_key
            .bootstrapping_key()
            .ntt_blind_rotate_interleaved_lookup_table_kernel_to(
                small_lwe,
                lookup_table,
                rotation_step,
                &mut self.main_glwe,
                parameters.glwe().cipher_modulus(),
                self.context.table(),
                &mut self.blind_rotation,
            );
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                self.server_key.glwe_key_switching_key().key_switch_to(
                    &self.main_glwe,
                    &mut self.switched,
                    parameters.glwe().cipher_modulus(),
                    self.context.table(),
                    &mut self.key_switching,
                );
                &self.switched
            }
            PbsOrder::KeyswitchBootstrap => &self.main_glwe,
        }
    }
}

/// Switches a kN LWE to the small secret through inverse extraction and ring KS.
/// The caller supplies buffers sized from the compatible context and server key;
/// all three ciphertext buffers are overwritten.
pub(crate) fn prepare_small_lwe<T, Table>(
    context: &TfheContext<T, Table>,
    server_key: &ServerKey<T>,
    input: &LweCiphertext<T>,
    main_glwe: &mut GlweCiphertext<Vec<T>>,
    switched: &mut GlweCiphertext<Vec<T>>,
    small_lwe: &mut LweCiphertext<T>,
    key_switching: &mut NttGlweKeySwitchingContext<T>,
) where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    let glwe = context.parameters().glwe();
    input.inverse_extract_glwe_to(main_glwe, glwe.poly_length(), glwe.cipher_modulus());
    server_key.glwe_key_switching_key().key_switch_to(
        main_glwe,
        switched,
        glwe.cipher_modulus(),
        context.table(),
        key_switching,
    );
    switched.extract_compact_lwe_to(small_lwe, glwe.poly_length(), glwe.cipher_modulus());
}
