use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::LookupTableCompiler;

use crate::TfheParameters;

impl<T, M, LM> TfheParameters<T, M, LM>
where
    T: FheUint,
    M: RingContext<T>,
    LM: RingContext<T>,
{
    /// Returns a [`LookupTableCompiler`] with outputs encoded at accumulator Q.
    ///
    /// The compiler owns its encoding state and can compile multiple programs.
    /// Default outputs belong to `0..t_in` and are decoded with the client's
    /// `decrypt` after the return path rescales Q to external q.
    ///
    /// Use [`LookupTableCompiler::try_with_output_codec`] to choose another output
    /// plaintext modulus. The supplied codec must use Q. Decode returned outputs
    /// with a codec having the same output plaintext modulus and ciphertext
    /// modulus q, applied to the client's `decrypt_phase` result.
    #[must_use]
    pub fn lookup_table_compiler(&self) -> LookupTableCompiler<T, LM, M> {
        let coefficient_modulus = self.accumulator_ntru().cipher_modulus();
        let output_codec = RoundedCodec::new(self.plain_modulus_value(), coefficient_modulus);
        LookupTableCompiler::try_new(
            self.accumulator_ntru().poly_length(),
            self.input_plaintext_codec(),
            coefficient_modulus,
            &output_codec,
        )
        .expect("the LUT output codec must use the accumulator modulus")
    }
}
