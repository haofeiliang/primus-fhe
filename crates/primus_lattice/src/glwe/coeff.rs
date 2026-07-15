use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
#[allow(unused_imports)]
use primus_poly::{ArrayBase, NttPolynomial, Polynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::{FieldContext, RingContext};

use super::NttGlwe;
use crate::lwe::Lwe;

/// A cryptographic structure for Module(General) Learning with Errors (MLWE, GLWE).
///
/// ## Structure of the `data`
///
/// |--a1--|....|--ak--|--b--|
///
/// where `a1`...`ak` and `b` are [`primus_poly::Polynomial`] with same poly length, `k` is the dimension.
#[derive(Clone)]
pub struct Glwe<S>(pub S)
where
    S: RawData,
    <S as RawData>::Elem: FheUint;

impl_common!(Glwe<S>);
impl_bytes_conversion!(Glwe<S>);
impl_zero!(Glwe<S>);
impl_iters!(Glwe);
impl_iter_sub_structure!(Glwe<S>, Polynomial, poly);
impl_basic_operation_single_modulus!(Glwe<S>);
impl_ntt!(Glwe<S>, NttGlwe);

impl<S, T> Glwe<S>
where
    S: RawData<Elem = T> + Data,
    T: FheUint,
{
    /// Extracts the constant coefficient as an LWE sample.
    ///
    /// A GLWE with `k` mask polynomials of length `N` produces an LWE of
    /// dimension `kN`. `output` must therefore have length `kN + 1`.
    pub fn extract_lwe_to<M, B>(&self, output: &mut Lwe<B>, poly_length: usize, modulus: M)
    where
        M: RingContext<T>,
        B: RawData<Elem = T> + DataMut,
    {
        assert!(poly_length > 0);
        debug_assert!(self.as_ref().len().is_multiple_of(poly_length));
        debug_assert!(output.dimension().is_multiple_of(poly_length));

        let mask_len = output.dimension();

        let (output_mask, output_body) = output.a_b_mut();
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
        B: RawData<Elem = T> + DataMut,
    {
        assert!(poly_length > 0);
        debug_assert!(self.as_ref().len().is_multiple_of(poly_length));

        let mask_len = self.as_ref().len() - poly_length;
        let active_key_len = output.dimension();
        assert!((1..mask_len).contains(&active_key_len));

        let (output_mask, output_body) = output.a_b_mut();
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

    /// Multiplies every GLWE component by `X^exponent` in
    /// `Z_q[X]/(X^N + 1)` and writes the result to `output`.
    ///
    /// `exponent` must belong to `[0, 2N)`.
    pub fn mul_monomial_to<M, B>(
        &self,
        exponent: usize,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: RawData<Elem = T> + DataMut,
    {
        self.monomial_to::<false, M, B>(exponent, output, poly_length, modulus);
    }

    /// Computes `output = self * (X^exponent - 1)` component-wise in
    /// `Z_q[X]/(X^N + 1)`.
    ///
    /// `exponent` must belong to `[0, 2N)`. Rotation and subtraction are
    /// fused into one coefficient pass.
    pub fn mul_monomial_sub_one_to<M, B>(
        &self,
        exponent: usize,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: RawData<Elem = T> + DataMut,
    {
        self.monomial_to::<true, M, B>(exponent, output, poly_length, modulus);
    }

    #[inline]
    fn monomial_to<const SUBTRACT_SELF: bool, M, B>(
        &self,
        exponent: usize,
        output: &mut Glwe<B>,
        poly_length: usize,
        modulus: M,
    ) where
        M: RingContext<T>,
        B: RawData<Elem = T> + DataMut,
    {
        debug_assert!(poly_length >= 2 && poly_length.is_power_of_two());
        debug_assert!(exponent < 2 * poly_length);
        debug_assert_eq!(self.as_ref().len(), output.as_ref().len());
        debug_assert_eq!(self.as_ref().len() % poly_length, 0);

        let shift = exponent & (poly_length - 1);
        let negate_rotation = exponent >= poly_length;
        let tail_len = poly_length - shift;

        if SUBTRACT_SELF {
            for (input, output) in self
                .as_ref()
                .chunks_exact(poly_length)
                .zip(output.as_mut().chunks_exact_mut(poly_length))
            {
                if negate_rotation {
                    for destination in 0..shift {
                        output[destination] =
                            modulus.reduce_sub(input[tail_len + destination], input[destination]);
                    }
                    for destination in shift..poly_length {
                        output[destination] = modulus.reduce_sub(
                            modulus.reduce_neg(input[destination - shift]),
                            input[destination],
                        );
                    }
                } else {
                    for destination in 0..shift {
                        output[destination] = modulus.reduce_sub(
                            modulus.reduce_neg(input[tail_len + destination]),
                            input[destination],
                        );
                    }
                    for destination in shift..poly_length {
                        output[destination] =
                            modulus.reduce_sub(input[destination - shift], input[destination]);
                    }
                }
            }
        } else {
            for (input, output) in self
                .as_ref()
                .chunks_exact(poly_length)
                .zip(output.as_mut().chunks_exact_mut(poly_length))
            {
                output[..shift].copy_from_slice(&input[tail_len..]);
                output[shift..].copy_from_slice(&input[..tail_len]);
                if negate_rotation {
                    modulus.reduce_neg_slice_assign(&mut output[shift..]);
                } else {
                    modulus.reduce_neg_slice_assign(&mut output[..shift]);
                }
            }
        }
    }

    /// Performs a multiplication on the `self` [`Glwe<S>`] with another `ntt_poly` [`NttPolynomial<A>`],
    /// store the result into `result` [`NttGlwe<B>`].
    #[inline]
    pub fn mul_ntt_polynomial_to<M, Table, A, B>(
        &self,
        ntt_poly: &NttPolynomial<A>,
        result: &mut NttGlwe<B>,
        modulus: M,
        ntt_table: &Table,
    ) where
        M: FieldContext<T>,
        Table: NttTable<ValueT = T>,
        A: RawData<Elem = T> + Data,
        B: RawData<Elem = T> + DataMut,
    {
        let ntt_poly_len = ntt_table.poly_length();

        result.0.copy_from_slice(self.as_ref());

        result.iter_ntt_poly_mut(ntt_poly_len).for_each(|mut poly| {
            ntt_table.transform_slice(poly.0);
            poly.mul_assign(ntt_poly, modulus);
        });
    }
}

#[cfg(test)]
mod tests {
    use primus_modulus::NativeModulus;

    use super::Glwe;
    use crate::lwe::Lwe;

    #[test]
    fn extracts_all_glwe_mask_polynomials_into_one_lwe() {
        let glwe = Glwe(vec![
            1u32, 2, 3, 4, // first mask
            5, 6, 7, 8, // second mask
            9, 10, 11, 12, // body
        ]);
        let mut lwe: Lwe<Vec<u32>> = Lwe::zero(8);

        glwe.extract_lwe_to(&mut lwe, 4, NativeModulus::new());

        assert_eq!(
            lwe.0,
            vec![
                1,
                4u32.wrapping_neg(),
                3u32.wrapping_neg(),
                2u32.wrapping_neg(),
                5,
                8u32.wrapping_neg(),
                7u32.wrapping_neg(),
                6u32.wrapping_neg(),
                9,
            ]
        );
    }

    #[test]
    fn compact_extraction_matches_the_active_prefix_of_full_extraction() {
        let glwe = Glwe(vec![
            1u32, 2, 3, 4, // first mask
            5, 6, 7, 8, // second mask
            9, 10, 11, 12, // body
        ]);
        let modulus = NativeModulus::new();
        let mut full: Lwe<Vec<u32>> = Lwe::zero(8);
        glwe.extract_lwe_to(&mut full, 4, modulus);

        for active_key_len in [1, 4, 5, 7, 8] {
            let mut compact: Lwe<Vec<u32>> = Lwe::zero(active_key_len);
            glwe.extract_compact_lwe_to(&mut compact, 4, modulus);

            assert_eq!(compact.a(), &full.a()[..active_key_len]);
            assert_eq!(compact.b(), full.b());
        }
    }
}
