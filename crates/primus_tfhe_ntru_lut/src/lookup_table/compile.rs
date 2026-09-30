//! Construction-only enumeration, encoding and polynomial interning.
//! Online lookup never retains the hash map or scratch used here.

use std::{
    collections::HashMap,
    hash::{DefaultHasher, Hasher},
};

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_integer::FheUint;
use primus_reduce::RingContext;
use primus_tfhe_ntru::TfheParameters;

use super::{
    HighPrecisionLookupTable, Layout, LookupTableError, OutputTable, checked_allocation_len,
};

impl<T: FheUint> HighPrecisionLookupTable<T> {
    /// Compiles a validated geometry without skipping any callback, even when a
    /// polynomial repeats. Check worst-case sizes before allocating or invoking the callback.
    pub(super) fn compile<M: RingContext<T>, LM: RingContext<T>>(
        parameters: &TfheParameters<T, M, LM>,
        layout: Layout,
        mut function: impl FnMut(usize, usize) -> T,
    ) -> Result<Self, LookupTableError> {
        let output_count = layout.config.output_chunk_count;
        checked_allocation_len::<T>(&[
            output_count,
            layout.polynomials_per_output,
            layout.polynomial_length,
        ])?;
        checked_allocation_len::<usize>(&[output_count, layout.polynomials_per_output])?;
        checked_allocation_len::<OutputTable>(&[output_count])?;

        let codec = RoundedCodec::new(
            parameters.plain_modulus_value(),
            parameters.accumulator_ntru().cipher_modulus(),
        );
        let digit_limit = parameters.plain_modulus_value() >> 1u32;
        let mut pool = PolynomialPool::new(layout.polynomial_length);
        let mut polynomial = vec![T::ZERO; layout.polynomial_length];
        let mut outputs = Vec::with_capacity(output_count);
        for output_chunk in 0..output_count {
            let mut ids = Vec::with_capacity(layout.polynomials_per_output);
            for prefix in 0..layout.polynomials_per_output {
                // x = prefix*K + z. Reuse the first K entries; the N-K tail stays zero.
                encode_entries(
                    prefix * layout.entries_per_polynomial,
                    output_chunk,
                    digit_limit,
                    &mut function,
                    &codec,
                    &mut polynomial[..layout.entries_per_polynomial],
                )?;
                ids.push(pool.get_or_insert_polynomial(&polynomial));
            }
            // Classify only after enumerating every prefix. Direct outputs retain
            // one ID instead of a repeated prefix array plus a separate flag.
            outputs.push(if ids.iter().all(|&id| id == ids[0]) {
                OutputTable::Direct(ids[0])
            } else {
                OutputTable::Select(ids.into_boxed_slice())
            });
        }
        Ok(Self {
            layout,
            coefficients: pool.coefficients.into_boxed_slice(),
            outputs: outputs.into_boxed_slice(),
            plaintext_modulus: parameters.plain_modulus_value(),
            input_modulus: parameters.external_lwe().cipher_modulus_value(),
            ring_modulus: parameters.accumulator_ntru().cipher_modulus_value(),
        })
    }
}

/// Fills the K meaningful coefficients in ascending input order. An invalid digit
/// stops at its original (input, output) pair; the caller owns the zero-padded tail.
fn encode_entries<T: FheUint, M: RingContext<T>>(
    first_input: usize,
    output_chunk: usize,
    digit_limit: T,
    function: &mut impl FnMut(usize, usize) -> T,
    codec: &RoundedCodec<T, M>,
    entries: &mut [T],
) -> Result<(), LookupTableError> {
    for (offset, coefficient) in entries.iter_mut().enumerate() {
        let input = first_input + offset;
        let digit = function(input, output_chunk);
        if digit >= digit_limit {
            return Err(LookupTableError::OutputChunkOutOfRange {
                input,
                output: output_chunk,
            });
        }
        *coefficient = codec.encode_value(digit, PlaintextEmbedding::Unsigned);
    }
    Ok(())
}

/// Owns the fixed polynomial stride and collision handling during construction.
/// Hashes only narrow the search; complete coefficient equality establishes identity.
struct PolynomialPool<T> {
    polynomial_length: usize,
    /// Unique polynomials concatenated at the fixed N-coefficient stride.
    coefficients: Vec<T>,
    /// Candidate physical IDs per hash; collisions are resolved by full comparison.
    buckets: HashMap<u64, Vec<usize>>,
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
    fn get_or_insert_polynomial(&mut self, polynomial: &[T]) -> usize {
        let n = self.polynomial_length;
        debug_assert_eq!(polynomial.len(), n);
        let bucket = self.buckets.entry(polynomial_hash(polynomial)).or_default();
        for &id in bucket.iter() {
            if self.coefficients[id * n..(id + 1) * n] == *polynomial {
                return id;
            }
        }
        let id = self.coefficients.len() / n;
        self.coefficients.extend_from_slice(polynomial);
        bucket.push(id);
        id
    }
}

/// Produces a candidate-bucket hash, not a proof of polynomial equality.
/// FheUint is Pod. The hash is construction-local, so native byte order is fine.
fn polynomial_hash<T: FheUint>(polynomial: &[T]) -> u64 {
    let mut hasher = DefaultHasher::new();
    hasher.write(bytemuck::cast_slice(polynomial));
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::{PolynomialPool, polynomial_hash};

    // A forced bucket collision must preserve unequal tails and still reuse duplicates.
    #[test]
    fn hash_collision_requires_full_polynomial_equality() {
        let mut pool = PolynomialPool::new(3);
        let first = [1u32, 2, 3];
        let second = [1u32, 2, 4];
        assert_eq!(pool.get_or_insert_polynomial(&first), 0);
        // Force an unrelated polynomial into the matching bucket without changing
        // the production hash path. It must be rejected by full equality.
        pool.buckets
            .entry(polynomial_hash(&second))
            .or_default()
            .push(0);
        assert_eq!(pool.get_or_insert_polynomial(&second), 1);
        assert_eq!(pool.get_or_insert_polynomial(&first), 0);
        assert_eq!(pool.get_or_insert_polynomial(&second), 1);
    }
}
