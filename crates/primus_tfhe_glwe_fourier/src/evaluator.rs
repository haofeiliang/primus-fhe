use primus_fft::{FftEngine, FftTable, TorusFftValue};
use primus_glwe::{FourierGlweKeySwitchingContext, GlweCiphertext};
use primus_lwe::LweCiphertext;
use primus_poly::Polynomial;
use primus_tfhe::{
    InterleavedLookupTable, LookupTable, ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
};
use primus_tfhe_glwe::PbsOrder;

use crate::{
    BootstrappingKey, FourierGlweBlindRotationContext, FourierGlweBootstrappingKey, ServerKey,
    SparseGlweBlindRotationContext, SparseGlweBootstrappingKey, TfheContext,
    error::TfheEvaluationError,
};

mod factorized;
pub use factorized::{FactorizedEvaluator, FourierFactorizedLookupTable};

/// Reusable Fourier workspace for programmable bootstrapping.
pub struct Evaluator<'a, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
{
    context: &'a TfheContext<T, Table>,
    server_key: &'a ServerKey<T>,
    fft: FftEngine<'a, Table>,
    blind_rotation: BlindRotation<'a, T>,
    key_switching: FourierGlweKeySwitchingContext<T>,
    // After BR: coefficient GLWE under the accumulator secret, in either order.
    main_glwe: GlweCiphertext<Vec<T>>,
    // Ring KS output under the padded small-LWE secret.
    switched: GlweCiphertext<Vec<T>>,
    small_lwe: LweCiphertext<T>,
}

// Pair each borrowed key with its own scratch once, avoiding mismatched variants
// and allocating only the workspace for the selected algorithm.
enum BlindRotation<'a, T: TorusFftValue> {
    Classic {
        key: &'a FourierGlweBootstrappingKey<T, primus_modulus::NativeModulus<T>>,
        scratch: FourierGlweBlindRotationContext<T>,
    },
    Sparse {
        key: &'a SparseGlweBootstrappingKey<T>,
        scratch: SparseGlweBlindRotationContext<T>,
    },
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
        Evaluator::apply_lookup_table_to(self, input, lookup_table, output)
    }
}

impl<T, Table> ProgrammableBootstrapInterleaved<T> for Evaluator<'_, T, Table>
where
    T: TorusFftValue,
    Table: FftTable,
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
    T: TorusFftValue,
    Table: FftTable,
{
    /// Creates an evaluator after checking the server-key layout and bases.
    ///
    /// # Correctness
    ///
    /// The server key must have been generated with this context's FFT table
    /// instance. The checks validate parameters, not Fourier table identity.
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
            blind_rotation: match server_key.bootstrapping_key() {
                BootstrappingKey::Classic(key) => BlindRotation::Classic {
                    key,
                    scratch: FourierGlweBlindRotationContext::new(key),
                },
                BootstrappingKey::Sparse(key) => BlindRotation::Sparse {
                    key,
                    scratch: SparseGlweBlindRotationContext::new(key),
                },
            },
            key_switching: key_switching_context,
            main_glwe: GlweCiphertext::zero(parameters.accumulator_glwe().glwe_len()),
            switched: GlweCiphertext::zero(parameters.glwe_key_switching().output().glwe_len()),
            small_lwe: LweCiphertext::zero(parameters.small_lwe().dimension()),
        })
    }

    pub(crate) fn fft_mut(&mut self) -> &mut FftEngine<'a, Table> {
        &mut self.fft
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
                self.keyswitch_accumulator();
                self.switched.extract_compact_lwe_to(
                    output,
                    glwe.poly_length(),
                    glwe.cipher_modulus(),
                );
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
                self.keyswitch_accumulator();
                for (index, output) in outputs.iter_mut().enumerate() {
                    self.switched.extract_compact_lwe_at_to(
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
    /// Returns the accumulator and FFT engine for CBS post-processing using
    /// the same workspace and table.
    #[inline]
    pub(crate) fn blind_rotate(
        &mut self,
        input: &LweCiphertext<T>,
        lookup_table: &Polynomial<Vec<T>>,
        rotation_step: usize,
    ) -> (&GlweCiphertext<Vec<T>>, &mut FftEngine<'a, Table>) {
        let parameters = self.context.parameters();
        let small_lwe = match parameters.pbs_order() {
            PbsOrder::BootstrapKeyswitch => input,
            PbsOrder::KeyswitchBootstrap => {
                self.keyswitch_input_to_small_lwe(input);
                &self.small_lwe
            }
        };
        match &mut self.blind_rotation {
            BlindRotation::Classic { key, scratch } => key
                .fourier_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table,
                    rotation_step,
                    &mut self.main_glwe,
                    &mut self.fft,
                    scratch,
                ),
            BlindRotation::Sparse { key, scratch } => key
                .fourier_blind_rotate_interleaved_lookup_table_kernel_to(
                    small_lwe,
                    lookup_table,
                    rotation_step,
                    &mut self.main_glwe,
                    &mut self.fft,
                    scratch,
                ),
        }
        (&self.main_glwe, &mut self.fft)
    }

    /// Switches `main_glwe` from the accumulator secret to the padded small
    /// secret in coefficient-domain `switched`, ready for compact extraction.
    /// Ordinary/interleaved PBS calls this only for BootstrapKeyswitch; the
    /// accumulator remains available for consumers needing its original secret.
    #[inline]
    fn keyswitch_accumulator(&mut self) {
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut self.switched,
            &mut self.fft,
            &mut self.key_switching,
        );
    }

    /// Converts an external kN LWE to `small_lwe` under the small-LWE secret,
    /// reusing `main_glwe` and `switched` for inverse extraction and ring KS.
    fn keyswitch_input_to_small_lwe(&mut self, input: &LweCiphertext<T>) {
        let glwe = self.context.parameters().accumulator_glwe();
        input.inverse_extract_glwe_to(
            &mut self.main_glwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
        self.server_key.glwe_key_switching_key().key_switch_to(
            &self.main_glwe,
            &mut self.switched,
            &mut self.fft,
            &mut self.key_switching,
        );
        self.switched.extract_compact_lwe_to(
            &mut self.small_lwe,
            glwe.poly_length(),
            glwe.cipher_modulus(),
        );
    }
}
