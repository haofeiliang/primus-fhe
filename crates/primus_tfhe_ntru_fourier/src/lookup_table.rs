//! Ordinary PBS and ManyLUT compilers from the context's message choices.

use primus_fft::{FftTable, TorusFftValue};
use primus_modulus::NativeModulus;

use crate::{LookupTableCompiler, LookupTableError, PbsMessageConfig, TfheContext};

impl<T, Table, LM> TfheContext<T, Table, LM>
where
    T: TorusFftValue,
    Table: FftTable,
    LM: primus_reduce::RingContext<T>,
{
    /// Prepares a Rounded compiler for the configured PBS/ManyLUT message domains.
    ///
    /// Copies small encoding state without allocating or borrowing this context.
    /// Input and returned messages use external q; LUT coefficients use accumulator
    /// Q. The output decoder is provided by [`Self::pbs_decryptor`]. Program
    /// capacity and output ranges are checked by the compiler methods.
    pub fn pbs_lookup_table_compiler(
        &self,
    ) -> Result<LookupTableCompiler<T, LM, NativeModulus<T>>, LookupTableError> {
        self.pbs_lookup_table_compiler_with_messages(self.parameters().messages())
    }

    /// Prepares a compiler with independent input/output plaintext moduli.
    ///
    /// Does not change defaults or existing clients. The configured input
    /// domain uses [`Self::encryptor`]; an independently prepared input codec
    /// must match `messages.input_modulus`. Decode returned outputs with
    /// a Rounded codec at external q for `messages.output_modulus`, bound through
    /// [`primus_tfhe_ntru::PbsParameters::decryptor_with_codec`].
    /// [`Self::pbs_decryptor`] uses the configured output modulus.
    /// Validates Rounded codecs at q/Q without preparing unused Scaled MVB state.
    /// Explicit codecs remain available through the parameter compiler factory.
    pub fn pbs_lookup_table_compiler_with_messages(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<LookupTableCompiler<T, LM, NativeModulus<T>>, LookupTableError> {
        let parameters = self.parameters();
        let codecs = parameters.pbs_codecs(messages)?;
        parameters.lookup_table_compiler(&codecs)
    }
}
