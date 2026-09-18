use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};
use primus_tfhe::{InterleavedLookupTable, LookupTable, LookupTableError};

use crate::TfheParameters;

impl<T, M> TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
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
        let coefficient_modulus = self.accumulator_ntru().cipher_modulus();
        self.check_output_modulus(output_codec)?;
        LookupTable::try_new_odd_full_domain(
            self.poly_length(),
            self.plain_modulus_value(),
            self.external_lwe().cipher_modulus(),
            coefficient_modulus,
            |input| encode_output(function(input), input, output_codec),
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
            .ok_or(LookupTableError::TableLengthOverflow)?;
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

    fn check_output_modulus<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
    ) -> Result<(), LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        if output_codec.ciphertext_modulus().explicit_value()
            != self.accumulator_ntru().cipher_modulus_value()
        {
            return Err(LookupTableError::OutputModulusMismatch);
        }
        Ok(())
    }

    /// Returns the front-half domain constrained by the NTRU rotation ring.
    fn front_half_domain_len(&self) -> Result<usize, LookupTableError> {
        primus_tfhe::front_half_domain_len(self.plain_modulus_value(), self.poly_length())
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
        let lwe = self.external_lwe();
        let coefficient_modulus = self.accumulator_ntru().cipher_modulus();
        self.check_output_modulus(output_codec)?;
        let plaintext_modulus = self.plain_modulus_value();
        LookupTable::try_new(
            domain_len,
            self.poly_length(),
            plaintext_modulus,
            lwe.cipher_modulus(),
            coefficient_modulus,
            |input| encode_output(output_at(input), input, output_codec),
        )
    }

    /// Encodes all output columns; the shared compiler owns their interleaved layout.
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
        let lwe = self.external_lwe();
        let coefficient_modulus = self.accumulator_ntru().cipher_modulus();
        self.check_output_modulus(output_codec)?;
        let plaintext_modulus = self.plain_modulus_value();
        InterleavedLookupTable::try_new(
            domain_len,
            self.poly_length(),
            output_count,
            plaintext_modulus,
            lwe.cipher_modulus(),
            coefficient_modulus,
            |input, output_index| {
                encode_output(output_at(input, output_index), input, output_codec)
            },
        )
    }
}

fn encode_output<T, OM>(
    output: T,
    input: usize,
    output_codec: &RoundedCodec<T, OM>,
) -> Result<T, LookupTableError>
where
    T: FheUint,
    OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
{
    if output >= output_codec.plaintext_modulus() {
        return Err(LookupTableError::OutputOutOfRange { input });
    }
    Ok(output_codec.encode_value(output, PlaintextEmbedding::Unsigned))
}
