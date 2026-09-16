use primus_encoding::RoundedCodec;
use primus_integer::FheUint;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_tfhe::{InterleavedLookupTable, LookupTable, LookupTableError};

use crate::{GlweTfheParameters, PlaintextEmbedding};

impl<T, LM, GM> GlweTfheParameters<T, LM, GM>
where
    T: FheUint,
    LM: RingContext<T>,
    GM: RingContext<T>,
{
    /// Compiles a unary function over the independently programmable front
    /// half `0..ceil(t_in/2)` of the input plaintext domain.
    ///
    /// Outputs use unsigned rounded encoding and must belong to
    /// `0..output_codec.plaintext_modulus()`.
    /// The codec's ciphertext modulus must equal the accumulator modulus; its plaintext
    /// modulus is independent of `t_in`. Ordinary PBS preserves this output encoding
    /// under the external LWE secret. Decode with this codec and the client's
    /// `decrypt_phase`, or use `decrypt` when it matches the parameter codec.
    pub fn compile_lookup_table_fn<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        let domain_len = self.front_half_domain_len()?;
        self.compile_lookup_table_outputs(output_codec, domain_len, function)
    }

    /// Slice form of [`Self::compile_lookup_table_fn`] with the same output-codec contract.
    /// Supply one output value for every front-half input.
    pub fn compile_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        let domain_len = self.front_half_domain_len()?;
        if outputs.len() != domain_len {
            return Err(LookupTableError::DomainLengthMismatch {
                expected: domain_len,
                actual: outputs.len(),
            });
        }
        self.compile_lookup_table_outputs(output_codec, domain_len, |input| outputs[input])
    }

    /// Compiles a unary function over all of `0..t_in` for odd `t_in`.
    ///
    /// Uses the output-codec contract of [`Self::compile_lookup_table_fn`].
    /// Requires `t_in <= N` and distinct signed-folded rotation centers; see
    /// [`LookupTable::try_new_odd_full_domain`] for interval and noise requirements.
    /// The callback is visited in folded-center order, not input order.
    pub fn compile_odd_full_domain_lookup_table_fn<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        let coefficient_modulus = self.glwe().cipher_modulus();
        if output_codec.ciphertext_modulus().explicit_value()
            != coefficient_modulus.explicit_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        LookupTable::try_new_odd_full_domain(
            self.glwe().poly_length(),
            self.plain_modulus_value(),
            self.small_lwe().cipher_modulus(),
            coefficient_modulus,
            |input| {
                let output = function(input);
                if output >= output_codec.plaintext_modulus() {
                    Err(LookupTableError::OutputOutOfRange { input })
                } else {
                    Ok(output_codec.encode_value(output, PlaintextEmbedding::Unsigned))
                }
            },
        )
    }

    /// Slice form of [`Self::compile_odd_full_domain_lookup_table_fn`].
    /// Supply exactly `t_in` outputs in plaintext input order.
    pub fn compile_odd_full_domain_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        let expected = self
            .plain_modulus_value()
            .try_into()
            .map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
        if outputs.len() != expected {
            return Err(LookupTableError::DomainLengthMismatch {
                expected,
                actual: outputs.len(),
            });
        }
        self.compile_odd_full_domain_lookup_table_fn(output_codec, |input| outputs[input])
    }

    /// Compiles `output_count` functions over the independently programmable
    /// front half `0..ceil(t_in/2)` of the input domain into one PBSManyLUT accumulator.
    ///
    /// Function arguments are `(input, output_index)`. All columns use `output_codec`,
    /// with the same output range and modulus contract as [`Self::compile_lookup_table_fn`].
    /// The output count must be nonzero. With `s = next_power_of_two(output_count)`,
    /// the front-half domain must satisfy `ceil(t_in/2) <= N / s`; unused slots are zero.
    /// See [`InterleavedLookupTable`] for the reduced rotation resolution.
    pub fn compile_interleaved_lookup_table_fn<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        function: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize, usize) -> T,
    {
        let domain_len = self.front_half_domain_len()?;
        self.compile_interleaved_lookup_table_outputs(
            output_codec,
            domain_len,
            output_count,
            function,
        )
    }

    /// Slice form of [`Self::compile_interleaved_lookup_table_fn`] with the same
    /// output-codec contract.
    ///
    /// `outputs` must contain `domain_len * output_count` values, ordered by
    /// plaintext input and then output index.
    pub fn compile_interleaved_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        outputs: &[T],
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        let domain_len = self.front_half_domain_len()?;
        let expected = domain_len
            .checked_mul(output_count)
            .ok_or(LookupTableError::ManyTableLengthOverflow)?;
        if outputs.len() != expected {
            return Err(LookupTableError::DomainLengthMismatch {
                expected,
                actual: outputs.len(),
            });
        }
        self.compile_interleaved_lookup_table_outputs(
            output_codec,
            domain_len,
            output_count,
            |input, output| outputs[input * output_count + output],
        )
    }

    /// Returns the front-half domain constrained by the GLWE rotation ring.
    fn front_half_domain_len(&self) -> Result<usize, LookupTableError> {
        primus_tfhe::front_half_domain_len(self.plain_modulus_value(), self.glwe().poly_length())
    }

    /// Validates and encodes user outputs before compiling the polynomial.
    fn compile_lookup_table_outputs<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        domain_len: usize,
        output_at: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        if output_codec.ciphertext_modulus().explicit_value()
            != self.glwe().cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        self.compile_encoded_lookup_table(domain_len, |input| {
            let output = output_at(input);
            if output >= output_codec.plaintext_modulus() {
                Err(LookupTableError::OutputOutOfRange { input })
            } else {
                Ok(output_codec.encode_value(output, PlaintextEmbedding::Unsigned))
            }
        })
    }

    fn compile_interleaved_lookup_table_outputs<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        domain_len: usize,
        output_count: usize,
        output_at: F,
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize, usize) -> T,
    {
        if output_codec.ciphertext_modulus().explicit_value()
            != self.glwe().cipher_modulus().explicit_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        let plaintext_modulus = self.plain_modulus_value();
        InterleavedLookupTable::try_new(
            domain_len,
            self.glwe().poly_length(),
            output_count,
            plaintext_modulus,
            self.small_lwe().cipher_modulus(),
            self.glwe().cipher_modulus(),
            |input, output_index| {
                let output = output_at(input, output_index);
                if output >= output_codec.plaintext_modulus() {
                    Err(LookupTableError::OutputOutOfRange { input })
                } else {
                    Ok(output_codec.encode_value(output, PlaintextEmbedding::Unsigned))
                }
            },
        )
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
        LookupTable::try_new(
            domain_len,
            glwe.poly_length(),
            lwe.plain_modulus_value(),
            lwe.cipher_modulus(),
            glwe.cipher_modulus(),
            encoded_output_at,
        )
    }
}
