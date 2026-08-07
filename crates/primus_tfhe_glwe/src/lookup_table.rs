use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{LookupTable, LookupTableError};

use crate::{GlweTfheParameters, PlaintextEmbedding};

impl<T, LM, GM> GlweTfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Compiles a unary function over the independently programmable front
    /// half of the plaintext domain.
    pub fn compile_lookup_table_fn<F>(
        &self,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        let domain_len = self.lookup_table_domain_len()?;
        self.compile_lookup_table_outputs(domain_len, function)
    }

    /// Compiles one output value for every front-half plaintext input.
    pub fn compile_lookup_table_slice(
        &self,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError> {
        let domain_len = self.lookup_table_domain_len()?;
        if outputs.len() != domain_len {
            return Err(LookupTableError::DomainLengthMismatch {
                expected: domain_len,
                actual: outputs.len(),
            });
        }
        self.compile_lookup_table_outputs(domain_len, |input| outputs[input])
    }

    /// Returns the front-half domain constrained by the GLWE rotation ring.
    fn lookup_table_domain_len(&self) -> Result<usize, LookupTableError> {
        primus_tfhe::lookup_table_domain_len(self.plain_modulus_value(), self.glwe().poly_length())
    }

    /// Validates and encodes user outputs before compiling the polynomial.
    fn compile_lookup_table_outputs<F>(
        &self,
        domain_len: usize,
        output_at: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        let plaintext_modulus = self.plain_modulus_value();
        let codec = self.glwe().plaintext_codec();
        self.compile_encoded_lookup_table(domain_len, |input| {
            let output = output_at(input);
            if output >= plaintext_modulus {
                Err(LookupTableError::OutputOutOfRange { input })
            } else {
                Ok(codec.encode_value(output, PlaintextEmbedding::Unsigned))
            }
        })
    }

    /// Compiles values already encoded in the GLWE accumulator modulus.
    pub(crate) fn compile_encoded_lookup_table<F>(
        &self,
        domain_len: usize,
        encoded_output_at: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> Result<T, LookupTableError>,
    {
        let lwe = self.small_lwe();
        let glwe = self.glwe();
        primus_tfhe::compile_encoded_lookup_table(
            domain_len,
            glwe.poly_length(),
            lwe.plaintext_codec(),
            lwe.cipher_modulus().explicit_value(),
            glwe.cipher_modulus(),
            encoded_output_at,
        )
    }
}
