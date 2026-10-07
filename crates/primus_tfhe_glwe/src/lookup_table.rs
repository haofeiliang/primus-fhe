use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{
    FactorizedPbsCodecs, LookupTableCompiler, LookupTableError, PbsMessageConfig, RoundedPbsCodecs,
};

use crate::TfheParameters;

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M> {
    /// Prepares input and output codecs for ordinary PBS or ManyLUT.
    ///
    /// [`PbsMessageConfig::new`] defaults to equal plaintext moduli; use
    /// [`PbsMessageConfig::with_output_modulus`] to change the output domain.
    /// All ciphertext roles share this family's modulus. Codec errors are
    /// reported here; LUT geometry and noise requirements remain operation-specific.
    pub fn pbs_codecs(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<RoundedPbsCodecs<T, M>, LookupTableError> {
        messages.try_rounded_codecs(self.cipher_modulus(), self.cipher_modulus())
    }

    /// Prepares Rounded input and Scaled output codecs for factorized MVB.
    ///
    /// Uses the same default/override rules as [`Self::pbs_codecs`]. Inherits
    /// [`PbsMessageConfig::try_factorized_codecs`]'s scale and error contracts;
    /// factorization-specific conditions are checked when compiling the program.
    pub fn factorized_pbs_codecs(
        &self,
        messages: PbsMessageConfig<T>,
    ) -> Result<FactorizedPbsCodecs<T, M>, LookupTableError> {
        messages.try_factorized_codecs(self.cipher_modulus(), self.cipher_modulus())
    }

    /// Creates a program compiler with explicit input encoding and matching outputs.
    ///
    /// The input codec must use the key's ciphertext modulus. The compiler owns
    /// its encoding state; program capacity is checked when compiling. Use
    /// [`LookupTableCompiler::try_with_output_codec`] for a different output
    /// message space, and decode with that output codec under the same secret.
    pub fn lookup_table_compiler(
        &self,
        input_codec: &RoundedCodec<T, M>,
    ) -> Result<LookupTableCompiler<T, M, M>, LookupTableError> {
        if input_codec.ciphertext_modulus().explicit_value()
            != self.cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::InputModulusMismatch);
        }
        LookupTableCompiler::try_new(
            self.blind_rotation_ggsw().poly_length(),
            input_codec,
            self.cipher_modulus(),
            input_codec,
        )
    }
}
