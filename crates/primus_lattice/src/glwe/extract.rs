//! Sample extraction and inverse embedding between GLWE and LWE layouts.

use primus_data::{Data, DataMut};
use primus_integer::FheUint;
use primus_reduce::RingContext;

use super::Glwe;
use crate::lwe::Lwe;

impl<S, T> Glwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Extracts the constant coefficient as an LWE sample.
    ///
    /// A GLWE with `k` mask polynomials of length `N` produces an LWE of
    /// dimension `kN`. `output` must therefore have length `kN + 1`.
    pub fn extract_lwe_to<M, B>(&self, output: &mut Lwe<B>, poly_length: usize, modulus: M)
    where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(poly_length > 0);
        debug_assert!(self.as_ref().len().is_multiple_of(poly_length));

        let mask_len = self.as_ref().len() - poly_length;
        let (output_mask, output_body) = output.a_b_mut();

        debug_assert_eq!(mask_len, output_mask.len());

        for (mask, extracted) in self.as_ref()[..mask_len]
            .chunks_exact(poly_length)
            .zip(output_mask.chunks_exact_mut(poly_length))
        {
            extracted[0] = mask[0];
            for (output, &input) in extracted[1..].iter_mut().zip(mask[1..].iter().rev()) {
                *output = modulus.reduce_neg(input);
            }
        }
        *output_body = self.as_ref()[mask_len];
    }

    /// Extracts coefficient `index` as an LWE sample.
    ///
    /// A GLWE with `k` mask polynomials of length `N` produces an LWE of
    /// dimension `kN`. `index` must be in `[0, N)`, and `output` must have
    /// dimension `kN`.
    pub fn extract_lwe_at_to<M, B>(
        &self,
        index: usize,
        output: &mut Lwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(index < poly_length, "GLWE extraction index is out of range");
        debug_assert!(
            self.as_ref().len().is_multiple_of(poly_length),
            "GLWE length is not divisible by the polynomial length"
        );

        let mask_len = self.as_ref().len() - poly_length;
        debug_assert_eq!(
            output.dimension(),
            mask_len,
            "LWE output dimension does not match the extracted GLWE key"
        );
        self.extract_lwe_prefix_at_to(index, output, poly_length, modulus);
    }

    /// Extracts the constant coefficient as an LWE sample while omitting mask
    /// coefficients paired with a zero-padded secret-key suffix.
    ///
    /// The active secret-key length is inferred from `output.dimension()` and
    /// must not exceed the full extracted dimension `kN`. For a GLWE key whose
    /// coefficient layout is `[s_lwe..., 0...]`, this directly produces an LWE
    /// sample under `s_lwe` without allocating an intermediate `kN`-dimension
    /// ciphertext.
    pub fn extract_compact_lwe_to<M, B>(&self, output: &mut Lwe<B>, poly_length: usize, modulus: M)
    where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(poly_length > 0);
        debug_assert!(self.as_ref().len().is_multiple_of(poly_length));

        let mask_len = self.as_ref().len() - poly_length;
        let (output_mask, output_body) = output.a_b_mut();
        debug_assert!((1..=mask_len).contains(&output_mask.len()));

        for (mask, extracted) in self.as_ref()[..mask_len]
            .chunks_exact(poly_length)
            .zip(output_mask.chunks_mut(poly_length))
        {
            extracted[0] = mask[0];
            for (output, &input) in extracted[1..].iter_mut().zip(mask[1..].iter().rev()) {
                *output = modulus.reduce_neg(input);
            }
        }
        *output_body = self.as_ref()[mask_len];
    }

    /// Extracts coefficient `index` as an LWE sample while omitting mask
    /// coefficients paired with a zero-padded secret-key suffix.
    ///
    /// `index` must be in `[0, N)`. The active secret-key length is inferred
    /// from `output.dimension()` and must not exceed the full `kN` mask.
    pub fn extract_compact_lwe_at_to<M, B>(
        &self,
        index: usize,
        output: &mut Lwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(index < poly_length, "GLWE extraction index is out of range");
        debug_assert!(
            self.as_ref().len().is_multiple_of(poly_length),
            "GLWE length is not divisible by the polynomial length"
        );

        let mask_len = self.as_ref().len() - poly_length;
        debug_assert!(
            (1..=mask_len).contains(&output.dimension()),
            "compact LWE output dimension exceeds the GLWE mask"
        );
        self.extract_lwe_prefix_at_to(index, output, poly_length, modulus);
    }

    #[inline]
    fn extract_lwe_prefix_at_to<M, B>(
        &self,
        index: usize,
        output: &mut Lwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        let (input_mask, input_body) = self.a_b_slices(poly_length);
        let (output_mask, output_body) = output.a_b_mut();

        for (mask, extracted) in input_mask
            .chunks_exact(poly_length)
            .zip(output_mask.chunks_mut(poly_length))
        {
            let positive_len = (index + 1).min(extracted.len());
            let (positive, negacyclic) = extracted.split_at_mut(positive_len);

            for (output, &input) in positive.iter_mut().zip(mask[..=index].iter().rev()) {
                *output = input;
            }
            for (output, &input) in negacyclic.iter_mut().zip(mask.iter().rev()) {
                *output = modulus.reduce_neg(input);
            }
        }
        *output_body = input_body[index];
    }
}

impl<S, T> Lwe<S>
where
    S: Data<Elem = T>,
    T: FheUint,
{
    /// Inserts this LWE sample into a GLWE ciphertext so that compact sample
    /// extraction recovers the original LWE sample exactly.
    ///
    /// For an LWE dimension `n` and `N = poly_length`, the output must contain
    /// `ceil(n / N) + 1` polynomials of length `N`. Unused coefficients in the
    /// final mask polynomial and all non-constant body coefficients are set to
    /// zero.
    pub fn inverse_extract_glwe_to<M, B>(
        &self,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: DataMut<Elem = T>,
    {
        debug_assert!(poly_length > 0);
        debug_assert!(self.dimension() > 0);

        let output_mask_len = self.dimension().next_multiple_of(poly_length);
        debug_assert_eq!(output.as_ref().len(), output_mask_len + poly_length);

        let (input_mask, input_body) = self.a_b();
        let (output_mask, output_body) = output.as_mut().split_at_mut(output_mask_len);
        output_mask.fill(T::ZERO);

        for (input, mask) in input_mask
            .chunks(poly_length)
            .zip(output_mask.chunks_exact_mut(poly_length))
        {
            mask[0] = input[0];
            for (output, &input) in mask[1..].iter_mut().rev().zip(&input[1..]) {
                *output = modulus.reduce_neg(input);
            }
        }

        output_body.fill(T::ZERO);
        output_body[0] = input_body;
    }
}
