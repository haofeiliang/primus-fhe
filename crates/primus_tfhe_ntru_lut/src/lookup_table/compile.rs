//! Construction-only enumeration, encoding and polynomial interning.
//! Online lookup never retains the hash map or scratch used here.

use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hasher},
};

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use super::selection::{SelectionCompiler, TableNodeId, TableOperation};

use super::{
    HighPrecisionLookupTable, Layout, LookupTableError, PolynomialId, checked_allocation_len,
};

impl<T: FheUint> HighPrecisionLookupTable<T> {
    /// Compiles a validated geometry without skipping any callback, even when a
    /// polynomial repeats. Check worst-case sizes before allocating or invoking the callback.
    pub(super) fn compile<M: RingContext<T>, LM: RingContext<T>>(
        ring_modulus: M,
        input_codec: &RoundedCodec<T, LM>,
        layout: Layout,
        mut function: impl FnMut(usize, usize) -> T,
    ) -> Result<Self, LookupTableError> {
        let output_count = layout.config.output_chunk_count;
        checked_allocation_len::<T>(&[
            output_count,
            layout.polynomials_per_output,
            layout.polynomial_length,
        ])?;
        checked_allocation_len::<PolynomialId>(&[output_count, layout.polynomials_per_output])?;
        // At most P-1 choice nodes plus P lifts per output. Also check the
        // branch-ID storage bound before callbacks, even though sharing reduces it.
        checked_allocation_len::<TableOperation>(&[
            output_count,
            layout.polynomials_per_output,
            2,
        ])?;
        checked_allocation_len::<TableNodeId>(&[output_count, layout.polynomials_per_output, 2])?;

        let codec = RoundedCodec::try_new(input_codec.plaintext_modulus(), ring_modulus)?;
        let radix = input_codec.plaintext_modulus() >> 1u32;
        let chunk_encodings = precompute_chunk_encodings(&codec, layout);
        // Both paths receive only validated digits from the filling helper.
        let encode_chunk = |chunk_value: T| match &chunk_encodings {
            Some(encodings) => {
                let index: usize = chunk_value.as_into();
                encodings[index]
            }
            None => codec.encode_value(chunk_value, PlaintextEmbedding::Unsigned),
        };
        let mut pool = PolynomialPool::new(layout.polynomial_length);
        let mut polynomial = vec![T::ZERO; layout.polynomial_length];
        let mut selection = SelectionCompiler::new(layout);
        for output_chunk in 0..output_count {
            let mut polynomial_ids = Vec::with_capacity(layout.polynomials_per_output);
            for table_prefix in 0..layout.polynomials_per_output {
                // x = prefix*K + z. Reuse the first K entries; the N-K tail stays zero.
                encode_output_chunk_coefficients(
                    table_prefix * layout.entries_per_polynomial,
                    output_chunk,
                    radix,
                    &mut function,
                    &encode_chunk,
                    &mut polynomial[..layout.entries_per_polynomial],
                )?;
                polynomial_ids.push(pool.get_or_insert_polynomial(&polynomial));
            }
            selection.add_output(polynomial_ids);
        }
        Ok(Self {
            layout,
            coefficients: pool.coefficients.into_boxed_slice(),
            selection: selection.finish(),
            plaintext_modulus: input_codec.plaintext_modulus(),
            input_modulus: input_codec.ciphertext_modulus().explicit_value(),
            ring_modulus: ring_modulus.explicit_value(),
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
    function: &mut impl FnMut(usize, usize) -> T,
    encode_chunk: &impl Fn(T) -> T,
    coefficients: &mut [T],
) -> Result<(), LookupTableError> {
    for (offset, coefficient) in coefficients.iter_mut().enumerate() {
        let input = first_input + offset;
        let chunk_value = function(input, output_chunk);
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

/// Construction-local hash used only to locate equality-check candidates.
/// A matching value does not establish polynomial identity.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
struct PolynomialHashValue(u64);

/// Owns the fixed polynomial stride and collision handling during construction.
/// Hashes only narrow the search; complete coefficient equality establishes identity.
struct PolynomialPool<T> {
    polynomial_length: usize,
    /// Unique polynomials concatenated at the fixed N-coefficient stride.
    coefficients: Vec<T>,
    /// Candidate physical IDs per hash; collisions are resolved by full comparison.
    buckets: HashMap<PolynomialHashValue, Vec<PolynomialId>>,
}

impl<T: FheUint> PolynomialPool<T> {
    /// Starts an empty pool with a fixed, positive polynomial length.
    fn new(polynomial_length: usize) -> Self {
        debug_assert!(polynomial_length > 0);
        Self {
            polynomial_length,
            coefficients: Vec::new(),
            buckets: HashMap::new(),
        }
    }

    /// Returns a stable physical ID, appending only if no identical polynomial exists.
    /// The input must contain exactly N coefficients, including its zero-padded tail.
    fn get_or_insert_polynomial(&mut self, polynomial: &[T]) -> PolynomialId {
        let n = self.polynomial_length;
        debug_assert_eq!(polynomial.len(), n);
        let bucket = self.buckets.entry(polynomial_hash(polynomial)).or_default();
        for &polynomial_id in bucket.iter() {
            if self.coefficients[polynomial_id.coefficient_range(n)] == *polynomial {
                return polynomial_id;
            }
        }
        let polynomial_id = PolynomialId(self.coefficients.len() / n);
        self.coefficients.extend_from_slice(polynomial);
        bucket.push(polynomial_id);
        polynomial_id
    }
}

/// Produces a candidate-bucket hash, not a proof of polynomial equality.
/// FheUint is Pod. The hash is construction-local, so native byte order is fine.
fn polynomial_hash<T: FheUint>(polynomial: &[T]) -> PolynomialHashValue {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytemuck::cast_slice(polynomial));
    PolynomialHashValue(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::{PolynomialId, PolynomialPool, polynomial_hash};

    // A forced bucket collision must preserve unequal tails and still reuse duplicates.
    #[test]
    fn hash_collision_requires_full_polynomial_equality() {
        let mut pool = PolynomialPool::new(3);
        let first = [1u32, 2, 3];
        let second = [1u32, 2, 4];
        assert_eq!(pool.get_or_insert_polynomial(&first), PolynomialId(0));
        // Force an unrelated polynomial into the matching bucket without changing
        // the production hash path. It must be rejected by full equality.
        pool.buckets
            .entry(polynomial_hash(&second))
            .or_default()
            .push(PolynomialId(0));
        assert_eq!(pool.get_or_insert_polynomial(&second), PolynomialId(1));
        assert_eq!(pool.get_or_insert_polynomial(&first), PolynomialId(0));
        assert_eq!(pool.get_or_insert_polynomial(&second), PolynomialId(1));
    }
}
