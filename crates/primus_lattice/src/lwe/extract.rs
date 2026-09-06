//! Inverse sample extraction into a coefficient-domain GLWE layout.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use super::Lwe;
use crate::glwe::Glwe;

impl<S, T> Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Inserts this LWE sample into a GLWE ciphertext so that compact sample
    /// extraction recovers the original LWE sample exactly.
    ///
    /// For a nonzero LWE dimension `n` and `N = poly_length`, the output must contain
    /// `ceil(n / N) + 1` polynomials of length `N`. Unused coefficients in the
    /// final mask polynomial and all non-constant body coefficients are set to
    /// zero. `poly_length` must be nonzero.
    pub fn inverse_extract_glwe_to<M, B>(
        &self,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        let output_mask_len = output.as_ref().len() - poly_length;

        debug_assert_eq!(
            output_mask_len,
            self.dimension().next_multiple_of(poly_length)
        );

        let output_slice = output.as_mut();
        output_slice.fill(T::ZERO);

        let (input_mask, input_body) = self.a_b();
        let (output_mask, output_body) = output_slice.split_at_mut(output_mask_len);

        for (input, mask) in input_mask
            .chunks(poly_length)
            .zip(output_mask.chunks_exact_mut(poly_length))
        {
            mask[0] = input[0];
            for (output, &input) in mask[1..].iter_mut().rev().zip(&input[1..]) {
                *output = modulus.reduce_neg(input);
            }
        }

        output_body[0] = input_body;
    }
}
