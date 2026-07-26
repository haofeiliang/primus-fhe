use core::range::Range;

use primus_integer::FheUint;
use primus_reduce::FieldContext;

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
}
