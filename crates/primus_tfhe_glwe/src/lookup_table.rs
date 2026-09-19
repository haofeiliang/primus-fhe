use primus_encoding::RoundedCodec;
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
    #[inline]
    pub fn compile_lookup_table_fn<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        LookupTable::try_from_fn(
            self.accumulator_glwe().poly_length(),
            self.input_plaintext_codec(),
            self.accumulator_glwe().cipher_modulus(),
            output_codec,
            function,
        )
    }

    /// Slice form of [`Self::compile_lookup_table_fn`] with the same output-codec contract.
    /// Supply one output value for every front-half input.
    #[inline]
    pub fn compile_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        LookupTable::try_from_slice(
            self.accumulator_glwe().poly_length(),
            self.input_plaintext_codec(),
            self.accumulator_glwe().cipher_modulus(),
            output_codec,
            outputs,
        )
    }

    /// Compiles a unary function over all of `0..t_in` for odd `t_in`.
    ///
    /// Uses the output-codec contract of [`Self::compile_lookup_table_fn`].
    /// Requires `t_in <= N` and distinct signed-folded rotation centers; see
    /// [`LookupTable::try_new_odd_full_domain`] for interval and noise requirements.
    /// The callback is visited in folded-center order, not input order.
    #[inline]
    pub fn compile_odd_full_domain_lookup_table_fn<OM, F>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        LookupTable::try_from_odd_full_domain_fn(
            self.accumulator_glwe().poly_length(),
            self.input_plaintext_codec(),
            self.accumulator_glwe().cipher_modulus(),
            output_codec,
            function,
        )
    }

    /// Slice form of [`Self::compile_odd_full_domain_lookup_table_fn`].
    /// Supply exactly `t_in` outputs in plaintext input order.
    #[inline]
    pub fn compile_odd_full_domain_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        outputs: &[T],
    ) -> Result<LookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        LookupTable::try_from_odd_full_domain_slice(
            self.accumulator_glwe().poly_length(),
            self.input_plaintext_codec(),
            self.accumulator_glwe().cipher_modulus(),
            output_codec,
            outputs,
        )
    }

    /// Compiles `output_count` functions over the independently programmable
    /// front half `0..ceil(t_in/2)` of the input domain into one PBSManyLUT accumulator.
    ///
    /// Function arguments are `(input, output_index)`. All columns use `output_codec`,
    /// with the same output range and modulus contract as [`Self::compile_lookup_table_fn`].
    /// The output count must be nonzero. With `s = next_power_of_two(output_count)`,
    /// the front-half domain must satisfy `ceil(t_in/2) <= N / s`; unused slots are zero.
    /// See [`InterleavedLookupTable`] for the reduced rotation resolution.
    #[inline]
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
        InterleavedLookupTable::try_from_fn(
            self.accumulator_glwe().poly_length(),
            self.input_plaintext_codec(),
            self.accumulator_glwe().cipher_modulus(),
            output_codec,
            output_count,
            function,
        )
    }

    /// Slice form of [`Self::compile_interleaved_lookup_table_fn`] with the same
    /// output-codec contract.
    ///
    /// `outputs` must contain `domain_len * output_count` values, ordered by
    /// plaintext input and then output index.
    #[inline]
    pub fn compile_interleaved_lookup_table_slice<OM>(
        &self,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        outputs: &[T],
    ) -> Result<InterleavedLookupTable<T>, LookupTableError>
    where
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        InterleavedLookupTable::try_from_slice(
            self.accumulator_glwe().poly_length(),
            self.input_plaintext_codec(),
            self.accumulator_glwe().cipher_modulus(),
            output_codec,
            output_count,
            outputs,
        )
    }
}
