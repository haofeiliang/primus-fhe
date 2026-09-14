//! Evaluation-point permutation in the standard bit-reversed NTT order.

use primus_modulus::PowOf2Modulus;
use primus_reduce::ReduceMul;

use crate::ReverseLsbs;

/// Precomputed `X -> X^degree` permutation in [`crate::NttTable`]'s
/// bit-reversed evaluation order.
///
/// The map depends only on degree and polynomial length. It preserves the
/// input residue range and performs neither arithmetic nor key switching.
#[derive(Clone)]
pub struct NttAutomorphismPermutation {
    sources: Vec<u32>,
}

impl NttAutomorphismPermutation {
    /// Constructs the permutation for an odd degree in `[1, 2N)`.
    ///
    /// # Panics
    /// Panics unless `N = poly_length` is a power of two of at least two,
    /// every evaluation index fits in `u32`, `2N` fits in `usize`, and the
    /// degree is odd and less than `2N`.
    #[must_use]
    pub fn new(degree: usize, poly_length: usize) -> Self {
        assert!(
            poly_length >= 2 && poly_length.is_power_of_two(),
            "automorphism polynomial length must be a power of two of at least two"
        );
        assert!(
            u32::try_from(poly_length - 1).is_ok(),
            "automorphism evaluation index exceeds u32"
        );
        let twice_n = poly_length
            .checked_mul(2)
            .expect("automorphism 2N overflows usize");
        assert!(
            degree < twice_n && degree % 2 == 1,
            "automorphism degree must be odd and less than 2N"
        );
        let log_n = poly_length.trailing_zeros();
        let modulus = PowOf2Modulus::new(twice_n);
        let mut sources = vec![0; poly_length];
        for i in 0..poly_length {
            let mapped_exponent = modulus.reduce_mul(degree, 2 * i + 1);
            let j = (mapped_exponent - 1) / 2;
            sources[i.reverse_lsbs(log_n)] = j.reverse_lsbs(log_n) as u32;
        }
        Self { sources }
    }

    /// Returns the number of evaluations in this permutation.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> usize {
        self.sources.len()
    }

    /// Writes the permuted evaluations without changing their residue range.
    ///
    /// # Correctness
    /// Both slices have exactly [`Self::poly_length`] entries in the
    /// bit-reversed negacyclic order specified by [`crate::NttTable`].
    /// The caller owns layout validation; only debug diagnostics run here.
    pub fn apply_to<T: Copy>(&self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), self.poly_length());
        debug_assert_eq!(output.len(), self.poly_length());
        for (output, &source) in output.iter_mut().zip(&self.sources) {
            *output = input[source as usize];
        }
    }
}
