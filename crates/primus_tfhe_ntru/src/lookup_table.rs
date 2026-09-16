use primus_encoding::PlaintextEmbedding;
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe::{InterleavedLookupTable, LookupTable, LookupTableError};

use crate::NtruTfheParameters;

impl<T, M> NtruTfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    /// Compiles a unary function over the independently programmable front
    /// half `0..ceil(t/2)` of the plaintext domain. Outputs must belong to `0..t`.
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

    /// Compiles `output_count` functions over the independently programmable
    /// front half `0..ceil(t/2)` of the plaintext domain into one PBSManyLUT accumulator.
    ///
    /// Function arguments are `(input, output_index)` and outputs belong to `0..t`.
    /// The output count must be nonzero. With `s = next_power_of_two(output_count)`,
    /// the front-half domain must satisfy `ceil(t/2) <= N / s`; unused slots are zero.
    /// See [`InterleavedLookupTable`] for the reduced rotation resolution.
    pub fn compile_interleaved_lookup_table_fn<F>(
        &self,
        output_count: usize,
        function: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        let domain_len = self.lookup_table_domain_len()?;
        self.compile_interleaved_lookup_table_outputs(domain_len, output_count, function)
    }

    /// Compiles input-major multi-output values into one PBSManyLUT
    /// accumulator.
    ///
    /// `outputs` must contain `domain_len * output_count` values, ordered by
    /// plaintext input and then output index.
    pub fn compile_interleaved_lookup_table_slice(
        &self,
        output_count: usize,
        outputs: &[T],
    ) -> Result<InterleavedLookupTable<T>, LookupTableError> {
        let domain_len = self.lookup_table_domain_len()?;
        let expected = domain_len
            .checked_mul(output_count)
            .ok_or(LookupTableError::ManyTableLengthOverflow)?;
        if outputs.len() != expected {
            return Err(LookupTableError::DomainLengthMismatch {
                expected,
                actual: outputs.len(),
            });
        }
        self.compile_interleaved_lookup_table_outputs(domain_len, output_count, |input, output| {
            outputs[input * output_count + output]
        })
    }

    /// Returns the front-half domain constrained by the NTRU rotation ring.
    fn lookup_table_domain_len(&self) -> Result<usize, LookupTableError> {
        primus_tfhe::lookup_table_domain_len(self.plain_modulus_value(), self.poly_length())
    }

    /// Validates plaintext outputs and compiles them with the shared LWE/NTRU scale.
    fn compile_lookup_table_outputs<F>(
        &self,
        domain_len: usize,
        output_at: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        F: Fn(usize) -> T,
    {
        let lwe = self.external_lwe();
        let plaintext_modulus = self.plain_modulus_value();
        LookupTable::try_new(
            domain_len,
            self.poly_length(),
            plaintext_modulus,
            lwe.cipher_modulus(),
            self.bootstrapping().ntru().cipher_modulus(),
            |input| {
                let output = output_at(input);
                if output >= plaintext_modulus {
                    Err(LookupTableError::OutputOutOfRange { input })
                } else {
                    Ok(lwe
                        .plaintext_codec()
                        .encode_value(output, PlaintextEmbedding::Unsigned))
                }
            },
        )
    }

    /// Encodes all output columns; the shared compiler owns their interleaved layout.
    fn compile_interleaved_lookup_table_outputs<F>(
        &self,
        domain_len: usize,
        output_count: usize,
        output_at: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        F: Fn(usize, usize) -> T,
    {
        let lwe = self.external_lwe();
        let plaintext_modulus = self.plain_modulus_value();
        InterleavedLookupTable::try_new(
            domain_len,
            self.poly_length(),
            output_count,
            plaintext_modulus,
            lwe.cipher_modulus(),
            self.bootstrapping().ntru().cipher_modulus(),
            |input, output_index| {
                let output = output_at(input, output_index);
                if output >= plaintext_modulus {
                    Err(LookupTableError::OutputOutOfRange { input })
                } else {
                    Ok(lwe
                        .plaintext_codec()
                        .encode_value(output, PlaintextEmbedding::Unsigned))
                }
            },
        )
    }
}
