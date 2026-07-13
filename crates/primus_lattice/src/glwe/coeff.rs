use primus_data::{Data, DataMut, DataOwned, RawData};
use primus_integer::FheUint;
use primus_ntt::NttTable;
#[allow(unused_imports)]
use primus_poly::{ArrayBase, NttPolynomial, Polynomial, PolynomialIter, PolynomialIterMut};
use primus_reduce::{FieldContext, RingContext};

use super::NttGlwe;

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
