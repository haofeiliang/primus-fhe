mod factorized;

pub use factorized::{FactorizedEvaluator, NttFactorizedLookupTable};

use primus_integer::FheUint;
use primus_ntt::MonomialNttTable;
use primus_poly::Polynomial;
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, LweCiphertext, ProgrammableBootstrap,
    ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

use crate::{
    ServerKey, TfheContext,
    blind_rotation::{BlindRotationWorkspace, blind_rotate_lookup_table_to},
};

/// Allocation-free online evaluator for exact NTT NTRU programmable bootstrapping.
pub struct Evaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey<T>,
    blind_rotation: BlindRotationWorkspace<T>,
}

impl<'a, T, Table> Evaluator<'a, T, Table>
where
    T: FheUint,
    Table: MonomialNttTable<ValueT = T>,
{
    /// Creates reusable evaluation state after checking the server key once.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
    ) -> Result<Self, TfheEvaluationError> {
        if !server_key.is_compatible(context.parameters()) {
            return Err(TfheEvaluationError::IncompatibleServerKey);
        }
        Ok(Self {
            context,
            server_key,
            blind_rotation: BlindRotationWorkspace::new(context.parameters()),
        })
    }

    /// Applies a compiled lookup table and allocates the returned ciphertext.
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

    /// Applies a compiled lookup table into an existing LWE allocation.
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
                parameters.poly_length(),
                parameters.plain_modulus_value(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            lwe_dimension,
            "PBS input dimension mismatch"
        );
        assert_eq!(
            output.dimension(),
            lwe_dimension,
            "PBS output dimension mismatch"
        );

        self.blind_rotate(input, lookup_table.polynomial(), 1);
        self.key_switch_accumulator();
        self.blind_rotation.scratch.extract_compact_lwe_to(
            output,
            parameters.ntru_key_switching().ntru().cipher_modulus(),
        );
    }

    /// Applies all interleaved lookup tables and allocates one ciphertext per output.
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

    /// Applies all interleaved tables into reusable output allocations.
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
                parameters.poly_length(),
                parameters.plain_modulus_value(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.accumulator_ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe_dimension();
        assert_eq!(
            input.dimension(),
            lwe_dimension,
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
                .all(|output| output.dimension() == lwe_dimension),
            "PBSManyLUT output ciphertext dimension mismatch"
        );

        self.blind_rotate(
            input,
            lookup_table.polynomial(),
            lookup_table.padded_output_count(),
        );
        self.key_switch_accumulator();
        for (index, output) in outputs.iter_mut().enumerate() {
            self.blind_rotation.scratch.extract_compact_lwe_at_to(
                index,
                output,
                parameters.ntru_key_switching().ntru().cipher_modulus(),
            );
        }
    }

    /// Writes the coefficient-domain BR result under the accumulator secret to
    /// `blind_rotation.current`. The caller checked input/LUT compatibility;
    /// `rotation_step` is the LUT's padded output count. No client key switch occurs.
    #[inline]
    fn blind_rotate(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) {
        let parameters = self.context.parameters();
        blind_rotate_lookup_table_to(
            self.server_key,
            input,
            lookup_table,
            rotation_step,
            &mut self.blind_rotation,
            parameters,
            self.context.table(),
        );
    }

    /// Switches the BR accumulator to the client ring secret in coefficient-domain
    /// `blind_rotation.scratch`, ready for compact LWE extraction. CBS consumes
    /// `blind_rotation.current` directly and does not perform this key switch.
    #[inline]
    fn key_switch_accumulator(&mut self) {
        let parameters = self.context.parameters();
        self.server_key.key_switching_key().key_switch_to(
            &self.blind_rotation.current,
            &mut self.blind_rotation.scratch,
            parameters.ntru_key_switching().ntru().cipher_modulus(),
            self.context.table(),
            self.blind_rotation.cmux.external_product(),
        );
    }
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
        Self::apply_lookup_table_to(self, input, lookup_table, output);
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
        Self::apply_interleaved_lookup_table_to(self, input, lookup_table, outputs);
    }
}
