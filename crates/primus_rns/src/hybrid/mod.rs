//! Hybrid RNS gadget decomposition for key switching.
//!
//! [`HybridRNS`] splits the ciphertext basis `Q` into non-empty contiguous
//! partitions. Each [`HybridRNSPartition`] owns the precomputation for the
//! approximate basis extension from that partition to its complement and the
//! auxiliary basis `P`. The resulting digits live in the combined `QP` basis.
//! `decomposition_count` (`dnum`) is the requested digit count,
//! `partition_moduli_count` (`alpha`) is the maximum number of `Q` moduli in a
//! digit, and `partition_count` (`beta`) is the actual number of non-empty
//! digits.
//!
//! The polynomial APIs use modulus-major storage and caller-owned scratch
//! buffers. They do not allocate in the online key-switching path.
//!
//! # References
//!
//! - OpenFHE `KeySwitchHYBRID` and `DCRTPoly::ApproxModDown`
//! - SEAL `BaseConverter`

use core::range::Range;

mod construction;
mod mod_down;
mod mod_up;
mod partition;

use primus_integer::FheUint;
use primus_reduce::FieldContext;

use crate::{BaseConverter, RNSBase};

/// One non-empty, contiguous partition of the ciphertext basis `Q`.
#[derive(Clone)]
pub struct HybridRNSPartition<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    q_range: Range<usize>,
    mod_up_converter: BaseConverter<T, M>,
}

/// Precomputed bases and converters for hybrid RNS key switching.
#[derive(Clone)]
pub struct HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    q_base: RNSBase<T, M>,
    p_base: RNSBase<T, M>,
    qp_base: RNSBase<T, M>,
    decomposition_count: usize,
    partition_moduli_count: usize,
    partitions: Vec<HybridRNSPartition<T, M>>,
    p_mod_q: Vec<T>,
    inv_p_mod_q: Vec<T>,
    mod_down_converter: BaseConverter<T, M>,
}

impl<T, M> HybridRNS<T, M>
where
    T: FheUint,
    M: FieldContext<T>,
{
    /// Returns the ciphertext basis `Q`.
    #[inline]
    pub fn q_base(&self) -> &RNSBase<T, M> {
        &self.q_base
    }

    /// Returns the auxiliary basis `P`.
    #[inline]
    pub fn p_base(&self) -> &RNSBase<T, M> {
        &self.p_base
    }

    /// Returns the combined basis `Q ∪ P`.
    #[inline]
    pub fn qp_base(&self) -> &RNSBase<T, M> {
        &self.qp_base
    }

    /// Returns the number of moduli in `Q`.
    #[inline]
    pub fn q_moduli_count(&self) -> usize {
        self.q_base.moduli_count()
    }

    /// Returns the number of moduli in `P`.
    #[inline]
    pub fn p_moduli_count(&self) -> usize {
        self.p_base.moduli_count()
    }

    /// Returns the number of moduli in `QP`.
    #[inline]
    pub fn qp_moduli_count(&self) -> usize {
        self.qp_base.moduli_count()
    }

    /// Returns the requested number of decomposition digits (`dnum`).
    ///
    /// This is an upper bound; [`partition_count`](Self::partition_count) can
    /// be smaller because every partition is non-empty and all but the last
    /// have the same size.
    #[inline]
    pub fn decomposition_count(&self) -> usize {
        self.decomposition_count
    }

    /// Returns the maximum number of `Q` moduli per partition (`alpha`).
    #[inline]
    pub fn partition_moduli_count(&self) -> usize {
        self.partition_moduli_count
    }

    /// Iterates over the non-empty `Q` partitions in basis order.
    #[inline]
    pub fn partitions(&self) -> impl ExactSizeIterator<Item = &HybridRNSPartition<T, M>> {
        self.partitions.iter()
    }

    /// Returns the actual number of non-empty partitions.
    #[inline]
    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    /// Returns the largest minimum ModUp scratch length among all partitions.
    #[inline]
    pub fn max_mod_up_scratch_len(&self, poly_length: usize) -> usize {
        self.partitions
            .iter()
            .map(|partition| partition.mod_up_scratch_len(poly_length))
            .max()
            .unwrap_or(0)
    }

    /// Returns the minimum scratch length required by polynomial ModDown.
    #[inline]
    pub fn mod_down_scratch_len(&self, poly_length: usize) -> usize {
        self.mod_down_converter
            .fast_convert_array_scratch_len(poly_length)
    }

    /// Returns the minimum scratch length required by scalar ModDown.
    #[inline]
    pub fn mod_down_scalar_scratch_len(&self) -> usize {
        self.mod_down_converter.fast_convert_scratch_len()
    }

    /// Returns `P mod q_i` in `Q`-basis order.
    #[inline]
    pub fn p_mod_q(&self) -> &[T] {
        &self.p_mod_q
    }

    /// Returns `P^-1 mod q_i` in `Q`-basis order.
    #[inline]
    pub fn inv_p_mod_q(&self) -> &[T] {
        &self.inv_p_mod_q
    }
}
