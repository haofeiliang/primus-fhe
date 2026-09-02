use aligned_vec::AVec;
use primus_factor::MultiplyFactor;

/// Computes a Barrett-preconditioned vector for a given bit shift.
///
/// For each `value` in `values`, computes `floor(value * 2^bit_shift / modulus)`.
pub(super) fn build_barrett_vector(values: &[u64], bit_shift: u32, modulus: u64) -> AVec<u64> {
    AVec::from_iter(
        64,
        values
            .iter()
            .map(|&value| MultiplyFactor::new(value, bit_shift, modulus).quotient()),
    )
}
