use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_fhe_core::{
    glwe::{FourierGlweKeySwitchingContext, GlweCiphertext},
    lwe::LweCiphertext,
};
use primus_tfhe::{Ciphertext, LookupTable, PbsOrder, ProgrammableBootstrap};

use crate::{FourierBlindRotationContext, ServerKey, TfheContext, error::TfheEvaluationError};

/// Reusable Fourier workspace for programmable bootstrapping.
pub struct Evaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey<T>,
    fft: FftEngine<'a, Table>,
    blind_rotation: FourierBlindRotationContext<T>,
    key_switching: FourierGlweKeySwitchingContext<T>,
    main_glwe: GlweCiphertext<Vec<T>>,
    switched: GlweCiphertext<Vec<T>>,
    small_lwe: LweCiphertext<T>,
}

impl<T, Table> ProgrammableBootstrap<T> for Evaluator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
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
    T: TorusFftValue,
    Table: FftTable,
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

        let key_switching = parameters.glwe_key_switching();
        let key_switching_context =
            FourierGlweKeySwitchingContext::new(key_switching.output().glwe_size());
        Ok(Self {
            context,
            server_key,
            fft: context.new_fft_engine(),
            blind_rotation: FourierBlindRotationContext::new(parameters.bootstrapping().size()),
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

    fn bootstrap_then_keyswitch(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    ) {
        let parameters = self.context.parameters();
        let glwe = parameters.glwe();
        self.server_key.bootstrapping_key().fourier_blind_rotate_to(
            input.as_lwe(),
            lookup_table.accumulator(),
            &mut self.main_glwe,
            parameters.bootstrapping(),
            &mut self.fft,
            &mut self.blind_rotation,
        );
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut self.switched,
            parameters.glwe_key_switching().output(),
            &mut self.fft,
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
        let parameters = self.context.parameters();
        let glwe = parameters.glwe();
        input.as_lwe().inverse_extract_glwe_to(
            &mut self.main_glwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut self.switched,
            parameters.glwe_key_switching().output(),
            &mut self.fft,
            &mut self.key_switching,
        );
        self.switched.extract_compact_lwe_to(
            &mut self.small_lwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
        self.server_key.bootstrapping_key().fourier_blind_rotate_to(
            &self.small_lwe,
            lookup_table.accumulator(),
            &mut self.main_glwe,
            parameters.bootstrapping(),
            &mut self.fft,
            &mut self.blind_rotation,
        );
        self.main_glwe.extract_lwe_to(
            output.as_lwe_mut(),
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
    }
}
