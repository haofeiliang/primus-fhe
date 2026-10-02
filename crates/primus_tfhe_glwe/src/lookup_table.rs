use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::LookupTableCompiler;

use crate::TfheParameters;

impl<T, M> TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Returns a [`LookupTableCompiler`] using the parameter codec for outputs.
    ///
    /// The compiler owns its encoding state and can compile multiple programs.
    /// Default outputs belong to `0..t_in` and are decoded with the client's
    /// `decrypt`. Use [`LookupTableCompiler::try_with_output_codec`] to choose a
    /// different output plaintext modulus; its ciphertext modulus must equal
    /// the accumulator modulus. Decode such outputs with that codec and the
    /// client's `decrypt_phase`.
    #[must_use]
    pub fn lookup_table_compiler(&self) -> LookupTableCompiler<T, M, M> {
        LookupTableCompiler::try_new(
            self.accumulator_glwe().poly_length(),
            self.input_plaintext_codec(),
            self.accumulator_glwe().cipher_modulus(),
            self.input_plaintext_codec(),
        )
        .expect("TFHE input and accumulator moduli must match")
    }
}
