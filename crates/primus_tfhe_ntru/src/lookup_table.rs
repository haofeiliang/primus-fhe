use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{LookupTableCompiler, LookupTableError};

use crate::TfheParameters;

impl<T, M, LM> TfheParameters<T, M, LM>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
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
