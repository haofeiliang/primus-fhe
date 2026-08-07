use primus_fhe_core::plaintext::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{
    LookupTable, LookupTableError, compile_encoded_lookup_table, lookup_table_domain_len,
};

use crate::NtruTfheParameters;

impl<T, M> NtruTfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
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

    /// Compiles one output for every front-half plaintext input.
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

    /// Returns the front-half domain constrained by the NTRU rotation ring.
    fn lookup_table_domain_len(&self) -> Result<usize, LookupTableError> {
        lookup_table_domain_len(self.plain_modulus_value(), self.poly_length())
    }

    /// Validates outputs and delegates the negacyclic polynomial layout to the
    /// shared TFHE compiler.
    fn compile_lookup_table_outputs<F>(
        &self,
        domain_len: usize,
        output_at: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        let plaintext_modulus = self.plain_modulus_value();
        let ntru = self.bootstrapping().ntru();
        compile_encoded_lookup_table(
            domain_len,
            self.poly_length(),
            self.external_lwe().plaintext_codec(),
            self.external_lwe().cipher_modulus_value(),
            ntru.cipher_modulus(),
            |input| {
                let output = output_at(input);
                if output >= plaintext_modulus {
                    Err(LookupTableError::OutputOutOfRange { input })
                } else {
                    Ok(ntru
                        .plaintext_codec()
                        .encode_value(output, PlaintextEmbedding::Unsigned))
                }
            },
        )
    }
}
