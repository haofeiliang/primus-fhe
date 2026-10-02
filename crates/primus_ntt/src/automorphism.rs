//! Evaluation-point permutation in the standard bit-reversed NTT order.

use primus_modulus::PowOf2Modulus;
use primus_poly::PolyLength;
use primus_reduce::ReduceMul;

use crate::ReverseLsbs;

/// Precomputed `X -> X^degree` permutation in [`crate::NttTable`]'s
/// bit-reversed evaluation order.
///
/// The map depends only on degree and polynomial length. It preserves the
/// input residue range and performs neither arithmetic nor key switching.
#[derive(Clone)]
pub struct NttAutomorphismPermutation {
    poly_length: PolyLength,
    sources: Vec<u32>,
}

impl NttAutomorphismPermutation {
    /// Constructs the permutation for an odd degree in `[1, 2N)`.
    ///
    /// # Panics
    /// Panics unless the degree is odd and less than `2N`.
    #[must_use]
    pub fn new(degree: usize, poly_length: PolyLength) -> Self {
        let n = poly_length.get();
        // The shared FHE bound makes both 2N and the stored u32 indices fit.
        let twice_n = 2 * n;
        assert!(
            degree < twice_n && degree & 1 == 1,
            "automorphism degree must be odd and less than 2N"
        );
        let log_n = poly_length.log_n();
        let modulus = PowOf2Modulus::new(twice_n);
        let mut sources = vec![0; n];
        for i in 0..n {
            let mapped_exponent = modulus.reduce_mul(degree, 2 * i + 1);
            let j = (mapped_exponent - 1) / 2;
            sources[i.reverse_lsbs(log_n)] = j.reverse_lsbs(log_n) as u32;
        }
        Self {
            poly_length,
            sources,
        }
    }

    /// Returns the number of evaluations in this permutation.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    /// Writes the permuted evaluations without changing their residue range.
    ///
    /// # Correctness
    /// Both slices have exactly [`Self::poly_length`] entries in the
    /// bit-reversed negacyclic order specified by [`crate::NttTable`].
    /// The caller owns layout validation; only debug diagnostics run here.
    pub fn apply_to<T: Copy>(&self, input: &[T], output: &mut [T]) {
        debug_assert_eq!(input.len(), self.poly_length().get());
        debug_assert_eq!(output.len(), self.poly_length().get());
        for (output, &source) in output.iter_mut().zip(&self.sources) {
            *output = input[source as usize];
        }
    }
}
