use primus_glwe::{GlweCiphertext, NttGadgetDomain, NttGlweKeySwitchingContext};
use primus_integer::FheUint;
use primus_lwe::LweCiphertext;
use primus_ntt::NttTable;
use primus_tfhe::{
    Ciphertext, LookupTable, ManyLookupTable, ProgrammableBootstrap, ProgrammableBootstrapMany,
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
    key_switching_domain: NttGadgetDomain<'a, T, primus_modulus::BarrettModulus<T>, Table>,
    bootstrapping_domain: NttGadgetDomain<'a, T, primus_modulus::BarrettModulus<T>, Table>,
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
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    ) {
        Evaluator::apply_lookup_table_to(self, input, lookup_table, output)
    }
}

impl<T, Table> ProgrammableBootstrapMany<T> for Evaluator<'_, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    #[inline]
    fn apply_many_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &ManyLookupTable<T>,
        outputs: &mut [Ciphertext<T>],
    ) {
        Evaluator::apply_many_lookup_table_to(self, input, lookup_table, outputs)
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

        let key_switching_domain = context.key_switching_domain();
        let bootstrapping_domain = context.bootstrapping_domain();
        let key_switching_context =
            NttGlweKeySwitchingContext::new(key_switching_domain.size().glwe_size());
        Ok(Self {
            context,
            server_key,
            key_switching_domain,
            blind_rotation: NttGlweBlindRotationContext::new(bootstrapping_domain.size()),
            bootstrapping_domain,
            key_switching: key_switching_context,
            main_glwe: GlweCiphertext::zero(parameters.glwe().glwe_len()),
            switched: GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len()),
            small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension()),
        })
    }

    /// Applies a compiled lookup table and returns a refreshed ciphertext in
    /// the external LWE dimension selected by the PBS order.
    ///
    /// # Panics
    ///
    /// Panics if the input dimension does not match this evaluator's context.
    pub fn apply_lookup_table(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
    ) -> Ciphertext<T> {
        let mut output = input.clone();
        self.apply_lookup_table_to(input, lookup_table, &mut output);
        output
    }

    /// Applies a compiled lookup table into an existing ciphertext allocation.
    ///
    /// # Panics
    ///
    /// Panics if either ciphertext dimension does not match this evaluator's
    /// context.
    pub fn apply_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    ) {
        let parameters = self.context.parameters();
        let expected_dimension = parameters.ciphertext_lwe_dimension();
        assert_eq!(input.dimension(), expected_dimension);
        assert_eq!(output.dimension(), expected_dimension);

        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                self.bootstrap_then_keyswitch(input, lookup_table, output)
            }
            PbsOrder::KeyswitchBootstrap => {
                self.keyswitch_then_bootstrap(input, lookup_table, output)
            }
        }
    }

    /// Applies several interleaved lookup tables using one blind rotation and
    /// returns one newly allocated ciphertext per output.
    pub fn apply_many_lookup_table(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &ManyLookupTable<T>,
    ) -> Vec<Ciphertext<T>> {
        let mut outputs = vec![input.clone(); lookup_table.output_count()];
        self.apply_many_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Applies several interleaved lookup tables into reusable ciphertext
    /// allocations using one blind rotation.
    ///
    /// Ring key switching is also shared by every output. `outputs` must have
    /// exactly the table's output count, and every ciphertext must use the
    /// external dimension selected by this context's PBS order.
    pub fn apply_many_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &ManyLookupTable<T>,
        outputs: &mut [Ciphertext<T>],
    ) {
        let parameters = self.context.parameters();
        let expected_dimension = parameters.ciphertext_lwe_dimension();
        assert_eq!(input.dimension(), expected_dimension);
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
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                self.server_key
                    .bootstrapping_key()
                    .ntt_blind_rotate_many_lookup_table_to(
                        input.as_lwe(),
                        lookup_table.polynomial(),
                        lookup_table.output_count(),
                        &mut self.main_glwe,
                        &self.bootstrapping_domain,
                        &mut self.blind_rotation,
                    );
                self.server_key.glwe_key_switching_key().key_switch_to(
                    &self.main_glwe,
                    &mut self.switched,
                    &self.key_switching_domain,
                    &mut self.key_switching,
                );
                for (index, output) in outputs.iter_mut().enumerate() {
                    self.switched.extract_compact_lwe_at_to(
                        index,
                        output.as_lwe_mut(),
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
            }
            PbsOrder::KeyswitchBootstrap => {
                self.prepare_small_lwe(input);
                self.server_key
                    .bootstrapping_key()
                    .ntt_blind_rotate_many_lookup_table_to(
                        &self.small_lwe,
                        lookup_table.polynomial(),
                        lookup_table.output_count(),
                        &mut self.main_glwe,
                        &self.bootstrapping_domain,
                        &mut self.blind_rotation,
                    );
                for (index, output) in outputs.iter_mut().enumerate() {
                    self.main_glwe.extract_lwe_at_to(
                        index,
                        output.as_lwe_mut(),
                        glwe.poly_length(),
                        glwe.cipher_modulus(),
                    );
                }
            }
        }
    }

    fn bootstrap_then_keyswitch(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    ) {
        let glwe = self.context.parameters().glwe();
        self.server_key
            .bootstrapping_key()
            .ntt_blind_rotate_lookup_table_to(
                input.as_lwe(),
                lookup_table.polynomial(),
                &mut self.main_glwe,
                &self.bootstrapping_domain,
                &mut self.blind_rotation,
            );
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut self.switched,
            &self.key_switching_domain,
            &mut self.key_switching,
        );
        self.switched.extract_compact_lwe_to(
            output.as_lwe_mut(),
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
    }

    fn keyswitch_then_bootstrap(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    ) {
        let glwe = self.context.parameters().glwe();
        self.prepare_small_lwe(input);
        self.server_key
            .bootstrapping_key()
            .ntt_blind_rotate_lookup_table_to(
                &self.small_lwe,
                lookup_table.polynomial(),
                &mut self.main_glwe,
                &self.bootstrapping_domain,
                &mut self.blind_rotation,
            );
        self.main_glwe.extract_lwe_to(
            output.as_lwe_mut(),
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
    }

    fn prepare_small_lwe(&mut self, input: &Ciphertext<T>) {
        let glwe = self.context.parameters().glwe();
        input.as_lwe().inverse_extract_glwe_to(
            &mut self.main_glwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut self.switched,
            &self.key_switching_domain,
            &mut self.key_switching,
        );
        self.switched.extract_compact_lwe_to(
            &mut self.small_lwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
    }
}
