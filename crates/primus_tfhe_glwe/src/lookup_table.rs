use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{LookupTableCompiler, LookupTableError};

use crate::TfheParameters;

impl<T: FheUint, M: RingContext<T>> TfheParameters<T, M> {
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
