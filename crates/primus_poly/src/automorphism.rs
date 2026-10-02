//! Precomputed coefficient permutations for negacyclic automorphisms.

use crate::PolyLength;
use primus_integer::{FheUint, WrappingNeg};
use primus_modulus::PowOf2Modulus;
use primus_reduce::{ReduceMul, RingContext};

#[derive(Clone, Copy)]
struct CoefficientSource {
    index: u32,
    negate: bool,
}

/// Precomputed coefficient permutation for `X -> X^degree` modulo `X^N + 1`.
///
/// The map depends only on the degree and polynomial length, not on a modulus
/// or secret key. Build it once and reuse it. Applying it to a ciphertext does
/// not perform the key switch needed for homomorphic automorphism.
#[derive(Clone)]
pub struct CoeffAutomorphismPermutation {
    poly_length: PolyLength,
    sources: Vec<CoefficientSource>,
}

impl CoeffAutomorphismPermutation {
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
            degree < twice_n && degree % 2 == 1,
            "automorphism degree must be odd and less than 2N"
        );
        let modulus = PowOf2Modulus::new(twice_n);
        let mut sources = vec![
            CoefficientSource {
                index: 0,
                negate: false
            };
            n
        ];
        for source in 0..n {
            let mapped = modulus.reduce_mul(source, degree);
            let negate = mapped >= n;
            let destination = if negate { mapped - n } else { mapped };
            sources[destination] = CoefficientSource {
                index: source as u32,
                negate,
            };
        }
        Self {
            poly_length,
            sources,
        }
    }

    /// Returns the number of coefficient positions in this permutation.
    #[inline]
    #[must_use]
    pub fn poly_length(&self) -> PolyLength {
        self.poly_length
    }

    /// Writes the automorphism of small signed integer coefficients.
    ///
    /// # Correctness
    /// Both slices contain exactly [`Self::poly_length`] coefficients. Every
    /// required negation must be representable in `T::SignedInteger`; in
    /// particular, a negated coefficient cannot be the signed minimum. This
    /// precondition is not checked. Use [`Self::apply_to`] on encoded residues
    /// when the full signed range must be supported.
    pub fn apply_signed_to<T: FheUint>(
        &self,
        input: &[T::SignedInteger],
        output: &mut [T::SignedInteger],
    ) {
        debug_assert_eq!(input.len(), self.poly_length().get());
        debug_assert_eq!(output.len(), self.poly_length().get());
        for (output, source) in output.iter_mut().zip(&self.sources) {
            let value = input[source.index as usize];
            *output = if source.negate {
                value.wrapping_neg()
            } else {
                value
            };
        }
    }

    /// Writes the automorphism of canonical coefficients modulo `modulus`.
    ///
    /// # Correctness
    /// Both slices contain exactly [`Self::poly_length`] coefficients. Input
    /// values are canonical modulo `modulus`; output is canonical too. Shape
    /// validation belongs to the owning caller; this kernel only debug-checks it.
    pub fn apply_to<T, M>(&self, input: &[T], output: &mut [T], modulus: M)
    where
        T: FheUint,
        M: RingContext<T>,
    {
        debug_assert_eq!(input.len(), self.poly_length().get());
        debug_assert_eq!(output.len(), self.poly_length().get());
        for (output, source) in output.iter_mut().zip(&self.sources) {
            let value = input[source.index as usize];
            *output = if source.negate {
                modulus.reduce_neg(value)
            } else {
                value
            };
        }
    }
}
