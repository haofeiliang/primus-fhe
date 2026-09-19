use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::{PrepareModulusSwitch, ReduceAdd, RingContext};

use super::{InterleavedLookupTable, LookupTable, front_half_domain_len};
use crate::LookupTableError;

impl<T: FheUint> LookupTable<T> {
    /// Compiles a function over the entire front half `0..ceil(t_in/2)`.
    ///
    /// Inputs use `input_codec`'s unsigned rounded encoding. Outputs must be in
    /// `0..output_codec.plaintext_modulus()` and are encoded unsigned. The output
    /// codec must use `coefficient_modulus`; its plaintext modulus is independent
    /// of the input domain. Encoding and capacity checks precede callback calls;
    /// center collisions and output-range errors stop compilation during filling.
    /// See [`Self::try_new`] for the underlying rotation and layout contract.
    #[inline]
    pub fn try_from_fn<IM, M, OM, F>(
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        let domain_len = front_half_domain_len(input_codec.plaintext_modulus(), poly_length)?;
        Self::from_outputs(
            domain_len,
            poly_length,
            input_codec,
            coefficient_modulus,
            output_codec,
            function,
        )
    }

    /// Slice form of [`Self::try_from_fn`], with one value per front-half input.
    /// Length errors precede output-codec and output-value validation.
    #[inline]
    pub fn try_from_slice<IM, M, OM>(
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        outputs: &[T],
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        let domain_len = front_half_domain_len(input_codec.plaintext_modulus(), poly_length)?;
        check_output_length(outputs.len(), domain_len)?;
        Self::from_outputs(
            domain_len,
            poly_length,
            input_codec,
            coefficient_modulus,
            output_codec,
            |input| outputs[input],
        )
    }

    /// Compiles all inputs `0..t_in` for odd `t_in`, encoding outputs as in
    /// [`Self::try_from_fn`]. The callback is visited in folded-center order;
    /// see [`Self::try_new_odd_full_domain`] for capacity and noise requirements.
    #[inline]
    pub fn try_from_odd_full_domain_fn<IM, M, OM, F>(
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        check_output_modulus(coefficient_modulus, output_codec)?;
        Self::try_new_odd_full_domain(
            poly_length,
            input_codec.plaintext_modulus(),
            input_codec.ciphertext_modulus(),
            coefficient_modulus,
            |input| encode_output(function(input), input, output_codec),
        )
    }

    /// Slice form of [`Self::try_from_odd_full_domain_fn`]. Supply exactly
    /// `t_in` outputs in plaintext input order. Length errors precede compilation.
    #[inline]
    pub fn try_from_odd_full_domain_slice<IM, M, OM>(
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        outputs: &[T],
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        let expected = input_codec
            .plaintext_modulus()
            .try_into()
            .map_err(|_| LookupTableError::PlaintextModulusTooLarge)?;
        check_output_length(outputs.len(), expected)?;
        Self::try_from_odd_full_domain_fn(
            poly_length,
            input_codec,
            coefficient_modulus,
            output_codec,
            |input| outputs[input],
        )
    }

    fn from_outputs<IM, M, OM, F>(
        domain_len: usize,
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize) -> T,
    {
        check_output_modulus(coefficient_modulus, output_codec)?;
        Self::try_new(
            domain_len,
            poly_length,
            input_codec.plaintext_modulus(),
            input_codec.ciphertext_modulus(),
            coefficient_modulus,
            |input| encode_output(function(input), input, output_codec),
        )
    }
}

impl<T: FheUint> InterleavedLookupTable<T> {
    /// Compiles `output_count` functions over the entire front-half input domain.
    ///
    /// The callback receives `(input, output_index)`. All outputs use the unsigned
    /// codec contract of [`LookupTable::try_from_fn`]. The output count must be
    /// nonzero; padded lanes are zero. See [`Self::try_new`] for capacity and
    /// reduced rotation resolution. Encoding and capacity checks precede callbacks;
    /// center collisions and output ranges are checked during filling.
    #[inline]
    pub fn try_from_fn<IM, M, OM, F>(
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize, usize) -> T,
    {
        let domain_len = front_half_domain_len(input_codec.plaintext_modulus(), poly_length)?;
        Self::from_outputs(
            domain_len,
            poly_length,
            input_codec,
            coefficient_modulus,
            output_codec,
            output_count,
            function,
        )
    }

    /// Slice form of [`Self::try_from_fn`]. Supply `ceil(t_in/2) * output_count`
    /// values ordered by input, then output index. Length errors precede
    /// output-codec and output-value validation.
    #[inline]
    pub fn try_from_slice<IM, M, OM>(
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        outputs: &[T],
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
    {
        let domain_len = front_half_domain_len(input_codec.plaintext_modulus(), poly_length)?;
        let expected = domain_len
            .checked_mul(output_count)
            .ok_or(LookupTableError::TableLengthOverflow)?;
        check_output_length(outputs.len(), expected)?;
        Self::from_outputs(
            domain_len,
            poly_length,
            input_codec,
            coefficient_modulus,
            output_codec,
            output_count,
            |input, output| outputs[input * output_count + output],
        )
    }

    fn from_outputs<IM, M, OM, F>(
        domain_len: usize,
        poly_length: usize,
        input_codec: &RoundedCodec<T, IM>,
        coefficient_modulus: M,
        output_codec: &RoundedCodec<T, OM>,
        output_count: usize,
        function: F,
    ) -> Result<Self, LookupTableError>
    where
        IM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        M: RingContext<T>,
        OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
        F: Fn(usize, usize) -> T,
    {
        check_output_modulus(coefficient_modulus, output_codec)?;
        Self::try_new(
            domain_len,
            poly_length,
            output_count,
            input_codec.plaintext_modulus(),
            input_codec.ciphertext_modulus(),
            coefficient_modulus,
            |input, output| encode_output(function(input, output), input, output_codec),
        )
    }
}

fn check_output_length(actual: usize, expected: usize) -> Result<(), LookupTableError> {
    if actual != expected {
        return Err(LookupTableError::DomainLengthMismatch { expected, actual });
    }
    Ok(())
}

fn check_output_modulus<T, M, OM>(
    modulus: M,
    codec: &RoundedCodec<T, OM>,
) -> Result<(), LookupTableError>
where
    T: FheUint,
    M: RingContext<T>,
    OM: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
{
    if codec.ciphertext_modulus().explicit_value() != modulus.explicit_value() {
        return Err(LookupTableError::OutputModulusMismatch);
    }
    Ok(())
}

#[inline]
fn encode_output<T, M>(
    output: T,
    input: usize,
    codec: &RoundedCodec<T, M>,
) -> Result<T, LookupTableError>
where
    T: FheUint,
    M: PrepareModulusSwitch<ValueT = T> + ReduceAdd<T, Output = T>,
{
    if output >= codec.plaintext_modulus() {
        return Err(LookupTableError::OutputOutOfRange { input });
    }
    Ok(codec.encode_value(output, PlaintextEmbedding::Unsigned))
}
