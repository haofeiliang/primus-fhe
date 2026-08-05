use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_fhe_core::{
    Ciphertext, FourierBlindRotationContext, FourierGlweKeySwitchingContext, GlweCiphertext,
    LookupTable, LweCiphertext, PbsOrder, ProgrammableBootstrap,
};

use crate::{ServerKey, TfheContext, error::TfheEvaluationError};

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
    ) -> Result<(), TfheEvaluationError> {
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
        let bootstrapping_key = server_key.bootstrapping_key();
        let bsk_size = bootstrapping_key.size();
        let key_switching_key = server_key.glwe_key_switching_key();
        let key_switching = parameters.glwe_key_switching();
        if bootstrapping_key.input_dimension() != parameters.small_lwe().dimension()
            || bootstrapping_key.input_modulus() != parameters.small_lwe().cipher_modulus_value()
            || bsk_size != parameters.bootstrapping().size()
            || bsk_size.glwe_size() != parameters.glwe().size()
            || key_switching_key.input_dimension() != key_switching.input_dimension()
            || key_switching_key.output_dimension() != key_switching.output_dimension()
            || key_switching_key.poly_length() != key_switching.poly_length()
        {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }

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
    pub fn apply_lookup_table(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
    ) -> Result<Ciphertext<T>, TfheEvaluationError> {
        let mut output = input.clone();
        self.apply_lookup_table_to(input, lookup_table, &mut output)?;
        Ok(output)
    }

    /// Applies a compiled lookup table into an existing ciphertext allocation.
    pub fn apply_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    ) -> Result<(), TfheEvaluationError> {
        let parameters = self.context.parameters();
        let expected_dimension = parameters.ciphertext_lwe_dimension();
        if input.dimension() != expected_dimension {
            return Err(TfheEvaluationError::InputDimensionMismatch {
                expected: expected_dimension,
                actual: input.dimension(),
            });
        }
        if output.dimension() != expected_dimension {
            return Err(TfheEvaluationError::OutputDimensionMismatch {
                expected: expected_dimension,
                actual: output.dimension(),
            });
        }

        let expected_len = parameters.glwe().glwe_len();
        let actual_len = lookup_table.accumulator().as_ref().len();
        if actual_len != expected_len {
            return Err(TfheEvaluationError::LookupTableLengthMismatch {
                expected: expected_len,
                actual: actual_len,
            });
        }

        let poly_length = parameters.glwe().poly_length();
        let modulus = parameters.glwe().cipher_modulus();
        match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => {
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
                    parameters.glwe_key_switching().output(),
                    &mut self.fft,
                    &mut self.key_switching,
                );
                self.switched
                    .extract_compact_lwe_to(&mut self.small_lwe, poly_length, modulus);
                self.server_key.bootstrapping_key().fourier_blind_rotate_to(
                    &self.small_lwe,
                    lookup_table.accumulator(),
                    &mut self.main_glwe,
                    parameters.bootstrapping(),
                    &mut self.fft,
                    &mut self.blind_rotation,
                );
                self.main_glwe
                    .extract_lwe_to(output.as_lwe_mut(), poly_length, modulus);
            }
        }
        Ok(())
    }
}
