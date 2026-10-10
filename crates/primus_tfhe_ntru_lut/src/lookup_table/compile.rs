//! Construction-only enumeration and encoding of the complete public table.

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_poly::PolynomialIterMut;
use primus_reduce::RingContext;

use super::{HighPrecisionLookupTable, Layout, LookupTableError, checked_allocation_len};

impl<T: FheUint> HighPrecisionLookupTable<T> {
    /// Compiles a validated geometry without skipping any callback, even when a
    /// polynomial repeats. Check the complete storage size before allocating or invoking the callback.
    pub(crate) fn compile<M: RingContext<T>, LM: RingContext<T>>(
        output_codec: &RoundedCodec<T, M>,
        input_codec: &RoundedCodec<T, LM>,
        layout: Layout,
        mut function: impl FnMut(usize, usize) -> Result<T, LookupTableError>,
    ) -> Result<Self, LookupTableError> {
        let output_count = layout.config.output_chunk_count;
        let coefficient_count = checked_allocation_len::<T>(&[
            output_count,
            layout.polynomials_per_output,
            layout.polynomial_length,
        ])?;

        let codec = output_codec;
        let radix = input_codec.plaintext_modulus() >> 1u32;
        let chunk_encodings = precompute_chunk_encodings(codec, layout);
        // Both paths receive only validated digits from the filling helper.
        let encode_chunk = |chunk_value: T| match &chunk_encodings {
            Some(encodings) => {
                let index: usize = chunk_value.as_into();
                encodings[index]
            }
            None => codec.encode_value(chunk_value, PlaintextEmbedding::Unsigned),
        };
        // Allocate every logical polynomial, even when coefficients repeat.
        // Only the first K positions are filled; each N-K tail remains zero.
        let mut coefficients = vec![T::ZERO; coefficient_count];
        let output_len = layout.polynomials_per_output * layout.polynomial_length;
        for (output_chunk, polynomials) in coefficients.chunks_exact_mut(output_len).enumerate() {
            for (table_prefix, polynomial) in
                PolynomialIterMut::new(polynomials, layout.polynomial_length).enumerate()
            {
                encode_output_chunk_coefficients(
                    table_prefix * layout.entries_per_polynomial,
                    output_chunk,
                    radix,
                    &mut function,
                    &encode_chunk,
                    &mut polynomial.0[..layout.entries_per_polynomial],
                )?;
            }
        }
        Ok(Self {
            layout,
            coefficients: coefficients.into_boxed_slice(),
            plaintext_modulus: input_codec.plaintext_modulus(),
            input_modulus: input_codec.ciphertext_modulus().explicit_value(),
            ring_modulus: output_codec.ciphertext_modulus().explicit_value(),
        })
    }
}

/// Prepares all M legal unsigned encodings only when they can be reused.
/// The cap bounds temporary storage to 2 KiB at u64; large radices and a single
/// M-entry output keep direct encoding. Nothing is retained by the compiled LUT.
fn precompute_chunk_encodings<T: FheUint, M: RingContext<T>>(
    codec: &RoundedCodec<T, M>,
    layout: Layout,
) -> Option<Vec<T>> {
    const MAX_PRECOMPUTED_RADIX: usize = 256;
    if layout.radix > MAX_PRECOMPUTED_RADIX
        || (layout.input_value_count == layout.radix && layout.config.output_chunk_count == 1)
    {
        return None;
    }
    // Layout validation proves every host index 0..M fits T. Batch encoding
    // selects the rounded modulus-switch kernel once for the entire small table.
    let mut encodings: Vec<_> = (0..layout.radix).map(T::as_from).collect();
    codec.encode_slice_assign(&mut encodings, PlaintextEmbedding::Unsigned);
    Some(encodings)
}

/// Fills the K meaningful coefficients in ascending input order. An invalid digit
/// stops at its original (input, output) pair; the caller owns the zero-padded tail.
fn encode_output_chunk_coefficients<T: FheUint>(
    first_input: usize,
    output_chunk: usize,
    radix: T,
    function: &mut impl FnMut(usize, usize) -> Result<T, LookupTableError>,
    encode_chunk: &impl Fn(T) -> T,
    coefficients: &mut [T],
) -> Result<(), LookupTableError> {
    for (offset, coefficient) in coefficients.iter_mut().enumerate() {
        let input = first_input + offset;
        let chunk_value = function(input, output_chunk)?;
        if chunk_value >= radix {
            return Err(LookupTableError::OutputChunkOutOfRange {
                input,
                output: output_chunk,
            });
        }
        // Check before indexing the precomputed encodings. Since M fits usize,
        // a valid chunk value also converts to its host index without truncation.
        *coefficient = encode_chunk(chunk_value);
    }
    Ok(())
}
