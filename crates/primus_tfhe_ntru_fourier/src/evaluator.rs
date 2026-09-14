use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_tfhe::{
    LookupTable, LweCiphertext, ManyLookupTable, ProgrammableBootstrap, ProgrammableBootstrapMany,
    TfheEvaluationError,
};

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
    server_key: &'a ServerKey<T>,
    fft: FftEngine<'a, Table>,
    blind_rotation: BlindRotationWorkspace<T>,
}

impl<'a, T, Table> Evaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates reusable evaluation state after checking the server key once.
    ///
    /// # Correctness
    ///
    /// The server key must have been generated with this context's FFT table
    /// instance. Parameter compatibility does not establish Fourier table identity.
    pub fn try_new(
        context: &'a TfheContext<T, Table>,
        server_key: &'a ServerKey<T>,
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
        let mut output = LweCiphertext::zero(self.context.parameters().external_lwe().dimension());
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
                parameters.bootstrapping().ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe().dimension();
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

        blind_rotate_lookup_table_to(
            self.server_key,
            input,
            lookup_table.polynomial(),
            1,
            &mut self.blind_rotation,
            parameters,
            &mut self.fft,
        );
        self.server_key.key_switching_key().key_switch_to(
            &self.blind_rotation.current,
            &mut self.blind_rotation.scratch,
            &mut self.fft,
            &mut self.blind_rotation.external_product,
        );
        self.blind_rotation
            .scratch
            .extract_compact_lwe_to(output, NativeModulus::new());
    }

    /// Applies all interleaved lookup tables and allocates one ciphertext per output.
    ///
    /// Shares one blind rotation and one ring key switch.
    ///
    /// Inherits [`ProgrammableBootstrapMany::apply_many_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics on an incompatible input dimension or LUT encoding/moduli/length.
    #[must_use]
    pub fn apply_many_lookup_table(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &ManyLookupTable<T>,
    ) -> Vec<LweCiphertext<T>> {
        let mut outputs = vec![input.clone(); lookup_table.output_count()];
        self.apply_many_lookup_table_to(input, lookup_table, &mut outputs);
        outputs
    }

    /// Applies all interleaved tables into reusable output allocations.
    ///
    /// Shares one blind rotation and one ring key switch.
    ///
    /// Inherits [`ProgrammableBootstrapMany::apply_many_lookup_table_to`]'s input encoding,
    /// key, noise and output-scale requirements.
    ///
    /// # Panics
    ///
    /// Panics before output writes on incompatible LUT encoding/moduli/length
    /// or ciphertext dimensions. A wrong output count is also rejected.
    pub fn apply_many_lookup_table_to(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &ManyLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        let parameters = self.context.parameters();
        assert!(
            lookup_table.is_compatible(
                parameters.poly_length(),
                parameters.plain_modulus_value(),
                parameters.external_lwe().cipher_modulus_value(),
                parameters.bootstrapping().ntru().cipher_modulus_value(),
            ),
            "PBS lookup-table encoding or polynomial length mismatch"
        );
        let lwe_dimension = parameters.external_lwe().dimension();
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

        blind_rotate_lookup_table_to(
            self.server_key,
            input,
            lookup_table.polynomial(),
            lookup_table.output_count(),
            &mut self.blind_rotation,
            parameters,
            &mut self.fft,
        );
        self.server_key.key_switching_key().key_switch_to(
            &self.blind_rotation.current,
            &mut self.blind_rotation.scratch,
            &mut self.fft,
            &mut self.blind_rotation.external_product,
        );
        for (index, output) in outputs.iter_mut().enumerate() {
            self.blind_rotation.scratch.extract_compact_lwe_at_to(
                index,
                output,
                NativeModulus::new(),
            );
        }
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
        input: &LweCiphertext<T>,
        lookup_table: &LookupTable<T>,
        output: &mut LweCiphertext<T>,
    ) {
        Self::apply_lookup_table_to(self, input, lookup_table, output);
    }
}

impl<T, Table> ProgrammableBootstrapMany<T> for Evaluator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    #[inline]
    fn apply_many_lookup_table_to(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &ManyLookupTable<T>,
        outputs: &mut [LweCiphertext<T>],
    ) {
        Self::apply_many_lookup_table_to(self, input, lookup_table, outputs);
    }
}
