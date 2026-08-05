use primus_fhe_core::{
    Ciphertext, GlweCiphertext, LookupTable, LweCiphertext, NttBlindRotationContext,
    NttGadgetDomain, NttGlweKeySwitchingContext, PbsOrder, ProgrammableBootstrap,
};
use primus_integer::FheUint;
use primus_ntt::NttTable;

use crate::{ServerKey, TfheContext, error::TfheEvaluationError};

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
    blind_rotation: NttBlindRotationContext<T>,
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
        let bootstrapping_key = server_key.bootstrapping_key();
        let common_size = bootstrapping_key.size();
        let key_switching_key = server_key.glwe_key_switching_key();
        let key_switching = parameters.glwe_key_switching();
        if bootstrapping_key.input_dimension() != parameters.small_lwe().dimension()
            || bootstrapping_key.input_modulus() != parameters.small_lwe().cipher_modulus_value()
            || common_size.glwe_size().dimension() != parameters.glwe().dimension()
            || common_size.glwe_size().poly_length() != parameters.glwe().poly_length()
            || common_size != parameters.bootstrapping().size()
            || bootstrapping_key.cipher_modulus() != Some(parameters.glwe().cipher_modulus_value())
            || key_switching_key.input_dimension() != key_switching.input_dimension()
            || key_switching_key.output_dimension() != key_switching.output_dimension()
            || key_switching_key.poly_length() != key_switching.poly_length()
        {
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
            blind_rotation: NttBlindRotationContext::new(bootstrapping_domain.size()),
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
    /// Panics if the input dimension or lookup-table accumulator length does
    /// not match this evaluator's context.
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
    /// Panics if either ciphertext dimension or the lookup-table accumulator
    /// length does not match this evaluator's context.
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

        let expected_len = parameters.glwe().glwe_len();
        assert_eq!(lookup_table.accumulator().as_ref().len(), expected_len);

        let poly_length = parameters.glwe().poly_length();
        let modulus = parameters.glwe().cipher_modulus();
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
                self.server_key.bootstrapping_key().ntt_blind_rotate_to(
                    input.as_lwe(),
                    lookup_table.accumulator(),
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
                self.switched
                    .extract_compact_lwe_to(output.as_lwe_mut(), poly_length, modulus);
            }
            PbsOrder::KeyswitchBootstrap => {
                input
                    .as_lwe()
                    .inverse_extract_glwe_to(&mut self.main_glwe, poly_length, modulus);
                self.server_key.glwe_key_switching_key().key_switch_to(
                    &self.main_glwe,
                    &mut self.switched,
                    &self.key_switching_domain,
                    &mut self.key_switching,
                );
                self.switched
                    .extract_compact_lwe_to(&mut self.small_lwe, poly_length, modulus);
                self.server_key.bootstrapping_key().ntt_blind_rotate_to(
                    &self.small_lwe,
                    lookup_table.accumulator(),
                    &mut self.main_glwe,
                    &self.bootstrapping_domain,
                    &mut self.blind_rotation,
                );
                self.main_glwe
                    .extract_lwe_to(output.as_lwe_mut(), poly_length, modulus);
            }
        }
    }
}
