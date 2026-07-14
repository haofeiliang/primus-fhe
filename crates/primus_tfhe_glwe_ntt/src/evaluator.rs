use primus_fhe_core::{
    Ciphertext, GlweCiphertext, LookupTable, LweCiphertext, NttBlindRotationContext,
    TfheEvaluationError, ntt_blind_rotate_to,
};
use primus_integer::FheUint;
use primus_ntt::NttTable;

use crate::{ServerKey, TfheContext};

/// Reusable NTT workspace for programmable bootstrapping.
pub struct Evaluator<'a, T, Table>
where
    T: FheUint,
    Table: NttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey<T>,
    blind_rotation: NttBlindRotationContext<T>,
    rotated: GlweCiphertext<Vec<T>>,
    extracted: LweCiphertext<T>,
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
        let common_size = bootstrapping_key.common_size();
        let key_switching_key = server_key.key_switching_key();
        if bootstrapping_key.input_dimension() != parameters.lwe().dimension()
            || common_size.dimension() != parameters.glwe().dimension()
            || common_size.poly_length() != parameters.glwe().poly_length()
            || bootstrapping_key.cipher_modulus() != Some(parameters.glwe().cipher_modulus_value())
            || key_switching_key.input_dimension() != parameters.glwe().secret_key_len()
            || key_switching_key.output_dimension() != parameters.lwe().dimension()
        {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }

        let glwe_dimension = parameters.glwe().dimension();
        let poly_length = parameters.glwe().poly_length();
        Ok(Self {
            context,
            server_key,
            blind_rotation: NttBlindRotationContext::new(glwe_dimension, poly_length),
            rotated: GlweCiphertext::zero(parameters.glwe().glwe_len()),
            extracted: LweCiphertext::zero(parameters.glwe().secret_key_len()),
        })
    }

    /// Applies a compiled lookup table and returns a refreshed small-LWE
    /// ciphertext.
    pub fn apply_lookup_table(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
    ) -> Result<Ciphertext<T>, TfheEvaluationError> {
        let parameters = self.context.parameters();
        let expected_dimension = parameters.lwe().dimension();
        if input.dimension() != expected_dimension {
            return Err(TfheEvaluationError::InputDimensionMismatch {
                expected: expected_dimension,
                actual: input.dimension(),
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

        ntt_blind_rotate_to(
            input.as_lwe(),
            lookup_table.accumulator(),
            &mut self.rotated,
            self.server_key.bootstrapping_key(),
            parameters.lwe(),
            parameters.bootstrapping(),
            self.context.table(),
            &mut self.blind_rotation,
        );
        self.rotated.extract_lwe_to(
            &mut self.extracted,
            parameters.glwe().poly_length(),
            parameters.glwe().cipher_modulus(),
        );
        let output = self
            .server_key
            .key_switching_key()
            .key_switch(&self.extracted, parameters.lwe().cipher_modulus());
        Ciphertext::try_from_lwe(output, expected_dimension)
            .map_err(|_| TfheEvaluationError::IncompatibleServerKey)
    }
}
