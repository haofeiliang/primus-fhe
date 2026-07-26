use core::range::Range;

use primus_integer::FheUint;
use primus_reduce::FieldContext;

use crate::BaseConverter;

use super::HybridRNSPartition;

impl<T, M> HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the indices of this partition in the full `Q` basis.
    #[inline]
    pub fn q_range(&self) -> Range<usize> {
        self.q_range
    }

    /// Returns the number of `Q` moduli in this partition.
    #[inline]
    pub fn moduli_count(&self) -> usize {
        self.q_range.end - self.q_range.start
    }

    /// Returns the approximate base converter from this partition to
    /// `complement(Q_j) ∪ P`.
    #[inline]
    pub fn mod_up_converter(&self) -> &BaseConverter<T, M> {
        &self.mod_up_converter
    }

    /// Returns the minimum scratch length required by
    /// [`approx_mod_up`](Self::approx_mod_up).
    #[inline]
    pub fn mod_up_scratch_len(&self, poly_length: usize) -> usize {
        self.mod_up_converter
            .fast_convert_array_scratch_len(poly_length)
    }

    /// Extends this partition of a `Q`-basis polynomial into one full `QP`
    /// hybrid digit.
    ///
    /// Both input and output use modulus-major layout. `scratch.len()` must be
    /// at least [`mod_up_scratch_len`](Self::mod_up_scratch_len). The partition
    /// limbs are copied exactly; the other limbs are produced by approximate
    /// RNS base conversion. A singleton partition ignores scratch.
    pub fn approx_mod_up(
        &self,
        polynomial_q: &[T],
        digit_qp: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let partition_elements = self
            .moduli_count()
            .checked_mul(poly_length)
            .expect("hybrid partition polynomial length overflow");
        let input_start = self.q_range.start * poly_length;
        let input_end = input_start + partition_elements;
        let expected_qp_len = (self.mod_up_converter.output_moduli_count() + self.moduli_count())
            .checked_mul(poly_length)
            .expect("hybrid QP polynomial length overflow");

        assert!(input_end <= polynomial_q.len());
        assert_eq!(digit_qp.len(), expected_qp_len);
        let partition_q = &polynomial_q[input_start..input_end];
        let (prefix_q, partition_and_suffix) = digit_qp.split_at_mut(input_start);
        let (partition_out, suffix_qp) = partition_and_suffix.split_at_mut(partition_elements);

        partition_out.copy_from_slice(partition_q);

        let output_polynomials = prefix_q
            .chunks_exact_mut(poly_length)
            .chain(suffix_qp.chunks_exact_mut(poly_length));
        self.mod_up_converter.fast_convert_array_to_polynomials(
            partition_q,
            output_polynomials,
            poly_length,
            scratch,
        );
    }
}
