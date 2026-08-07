use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_tfhe::{Ciphertext, LookupTable, ProgrammableBootstrap, TfheEvaluationError};

use crate::{
    ServerKey, TfheContext,
    bootstrapping_key::{BlindRotationWorkspace, blind_rotate_lookup_table_to},
};

/// Allocation-free online evaluator for Fourier NTRU programmable bootstrapping.
pub struct Evaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey,
    fft: FftEngine<'a, Table>,
    blind_rotation: BlindRotationWorkspace<T>,
}

impl<'a, T, Table> Evaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates reusable evaluation state after checking the server key once.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey,
    ) -> Result<Self, TfheEvaluationError> {
        if !server_key.is_compatible(context.parameters()) {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }
        let poly_length = context.parameters().poly_length();
        Ok(Self {
            context,
            server_key,
            fft: context.new_fft_engine(),
            blind_rotation: BlindRotationWorkspace::new(poly_length),
        })
    }

    /// Applies a compiled lookup table and allocates the returned ciphertext.
    pub fn apply_lookup_table(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
    ) -> Ciphertext<T> {
        let mut output = Ciphertext::from_lwe(primus_lattice::lwe::Lwe::zero(
            self.context.parameters().external_lwe().dimension(),
        ));
        self.apply_lookup_table_to(input, lookup_table, &mut output);
        output
    }

    /// Applies a compiled lookup table into an existing LWE allocation.
    ///
    /// # Panics
    ///
    /// Panics if an input or output LWE dimension differs from `N`.
    pub fn apply_lookup_table_to(
        &mut self,
        input: &Ciphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut Ciphertext<T>,
    ) {
        let parameters = self.context.parameters();
        let lwe_dimension = parameters.external_lwe().dimension();
        assert_eq!(input.dimension(), lwe_dimension);
        assert_eq!(output.dimension(), lwe_dimension);

        blind_rotate_lookup_table_to(
            self.server_key,
            input.as_lwe(),
            lookup_table.polynomial(),
            &mut self.blind_rotation,
            parameters,
            &mut self.fft,
        );
        self.server_key.key_switching_key().key_switch_to(
            &self.blind_rotation.current,
            &mut self.blind_rotation.scratch,
            parameters.key_switching(),
            &mut self.fft,
            &mut self.blind_rotation.external_product,
        );
        self.blind_rotation
            .scratch
            .extract_compact_lwe_to(output.as_lwe_mut(), NativeModulus::new());
    }
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
        Self::apply_lookup_table_to(self, input, lookup_table, output);
    }
}
