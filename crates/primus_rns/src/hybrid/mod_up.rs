use primus_integer::FheUint;
use primus_reduce::FieldContext;

use super::HybridRNSPartition;

impl<T, M> HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
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
        polynomial_mod_q: &[T],
        digit_mod_qp: &mut [T],
        poly_length: usize,
        scratch: &mut [T],
    ) {
        let partition_len = self
            .moduli_count()
            .checked_mul(poly_length)
            .expect("hybrid partition polynomial length overflow");
        let partition_start = self.q_range.start * poly_length;
        let partition_end = partition_start + partition_len;
        let expected_digit_len = (self.mod_up_converter.output_moduli_count()
            + self.moduli_count())
        .checked_mul(poly_length)
        .expect("hybrid QP polynomial length overflow");

        assert!(partition_end <= polynomial_mod_q.len());
        assert_eq!(digit_mod_qp.len(), expected_digit_len);

        let partition_mod_q = &polynomial_mod_q[partition_start..partition_end];
        let (prefix_mod_q, partition_and_suffix) = digit_mod_qp.split_at_mut(partition_start);
        let (partition_output, suffix_mod_qp) = partition_and_suffix.split_at_mut(partition_len);
        partition_output.copy_from_slice(partition_mod_q);

        let converted_limbs = prefix_mod_q
            .chunks_exact_mut(poly_length)
            .chain(suffix_mod_qp.chunks_exact_mut(poly_length));
        self.mod_up_converter.fast_convert_array_to_polynomials(
            partition_mod_q,
            converted_limbs,
            poly_length,
            scratch,
        );
    }
}
