use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{
    FactorizedPbsCodecs, LookupTableCompiler, LookupTableError, PbsMessageConfig, RoundedPbsCodecs,
};

use crate::TfheParameters;

impl<T, M, LM> TfheParameters<T, M, LM>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    /// Prepares input and output codecs for ordinary PBS or ManyLUT.
    ///
    /// [`PbsMessageConfig::new`] defaults to equal plaintext moduli; use
    /// [`PbsMessageConfig::with_output_modulus`] to change the output domain.
    /// Derives the LUT output at Q and returned output at q from the same choice.
    /// Rejects invalid codecs in either domain; this does not establish LUT
    /// capacity or a noise budget for the Q→q return.
    pub fn pbs_codecs(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<RoundedPbsCodecs<T, M, LM>, LookupTableError> {
        messages.try_rounded_codecs(
            self.external_lwe().cipher_modulus(),
            self.accumulator_ntru().cipher_modulus(),
        )
    }

    /// Prepares Rounded input and Scaled output codecs for factorized MVB.
    ///
    /// Uses the same default/override rules as [`Self::pbs_codecs`], deriving
    /// both Q/q outputs together. Inherits
    /// [`PbsMessageConfig::try_factorized_codecs`]'s scale and error contracts;
    /// factorization-specific conditions are checked when compiling the program.
    pub fn factorized_pbs_codecs(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<FactorizedPbsCodecs<T, M, LM>, LookupTableError> {
        messages.try_factorized_codecs(
            self.external_lwe().cipher_modulus(),
            self.accumulator_ntru().cipher_modulus(),
        )
    }

    /// Returns a [`LookupTableCompiler`] with outputs encoded at accumulator Q.
    ///
    /// Checks that `input_codec` uses external q and that its plaintext modulus
    /// is representable at accumulator Q. The compiler owns its encoding state
    /// and can compile multiple programs.
    /// Default outputs belong to `0..t_in` and are decoded with the client's
    /// `decrypt` after the return path rescales Q to external q.
    ///
    /// Use [`LookupTableCompiler::try_with_output_codec`] to choose another output
    /// plaintext modulus. The supplied codec must use Q. Decode returned outputs
    /// with a codec having the same output plaintext modulus and ciphertext
    /// modulus q, applied to the client's `decrypt_phase` result.
    pub fn lookup_table_compiler(
        &self,
        input_codec: &RoundedCodec<T, LM>,
    ) -> Result<LookupTableCompiler<T, LM, M>, LookupTableError> {
        if input_codec.ciphertext_modulus().explicit_value()
            != self.external_lwe().cipher_modulus_value()
        {
            return Err(LookupTableError::InputModulusMismatch);
        }
        let coefficient_modulus = self.accumulator_ntru().cipher_modulus();
        let output_codec =
            RoundedCodec::try_new(input_codec.plaintext_modulus(), coefficient_modulus)?;
        LookupTableCompiler::try_new(
            self.accumulator_ntru().poly_length(),
            input_codec,
            coefficient_modulus,
            &output_codec,
        )
    }
}
