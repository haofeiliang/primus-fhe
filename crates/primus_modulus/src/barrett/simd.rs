//! SIMD Barrett modulus implementation and dot-product helper.

use primus_integer::{CarryingAdd, CarryingMul, SimdArray, SimdUnsignedInteger, WideningMul};
use primus_reduce::prelude::*;

use super::BarrettModulus;

use crate::common::compact;

/// A lane-wise Barrett context used by SIMD kernels.
///
/// It broadcasts a scalar modulus and its reciprocal to every SIMD lane. The
/// scalar modulus must satisfy `1 < value < 2^(T::BITS - 2)`.
#[derive(Debug, Clone, Copy)]
pub struct SimdBarrettModulus<T: SimdUnsignedInteger> {
    value: T::SimdT,
    ratio: [T::SimdT; 2],
}

impl<T: SimdUnsignedInteger> SimdBarrettModulus<T> {
    /// Creates a [`SimdBarrettModulus<T>`] from a modulus and its precomputed reciprocal.
    ///
    /// # Correctness
    ///
    /// `value` must satisfy `1 < value < 2^(T::BITS - 2)`, and `ratio` must
    /// equal `floor(B² / value)` where `B = 2^(T::BITS)`. Prefer converting a
    /// validated [`BarrettModulus`] when runtime construction is sufficient.
    pub fn new(value: T, ratio: [T; 2]) -> Self {
        Self {
            value: T::SimdT::splat(value),
            ratio: [T::SimdT::splat(ratio[0]), T::SimdT::splat(ratio[1])],
        }
    }
}

impl<T: SimdUnsignedInteger> SimdBarrettModulus<T> {
    /// Lazily reduces a lane-wise 2-limb value `(hi * B + lo)` modulo this modulus.
    #[inline]
    pub fn lazy_reduce_wide(&self, lo: T::SimdT, hi: T::SimdT) -> T::SimdT {
        let ah = lo.widening_mul_hw(self.ratio[0]);

        let b = lo.carrying_mul(self.ratio[1], ah);
        let c = hi.widening_mul(self.ratio[0]);

        let d = hi * self.ratio[1];

        let bch = b.1.carrying_add(c.1, b.0.overflowing_add(c.0).1).0;

        let q = d + bch;

        // Subtract the estimated multiple modulo `B` lane-wise.
        lo - (q * self.value)
    }

    /// Reduces a lane-wise 2-limb value `(hi * B + lo)` modulo this modulus.
    #[inline]
    pub fn reduce_wide(&self, lo: T::SimdT, hi: T::SimdT) -> T::SimdT {
        compact::simd::reduce_once::<T>(self.value, self.lazy_reduce_wide(lo, hi))
    }
}

impl<T: SimdUnsignedInteger> From<BarrettModulus<T>> for SimdBarrettModulus<T> {
    #[inline]
    fn from(modulus: BarrettModulus<T>) -> Self {
        let ratio = modulus.ratio();
        Self {
            value: T::SimdT::splat(modulus.value()),
            ratio: [T::SimdT::splat(ratio[0]), T::SimdT::splat(ratio[1])],
        }
    }
}

impl<T: SimdUnsignedInteger> LazyReduce<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn lazy_reduce(self, value: T::SimdT) -> Self::Output {
        let tmp = value.widening_mul_hw(self.ratio[0]);
        let q = value.carrying_mul_hw(self.ratio[1], tmp);

        value - (q * self.value)
    }
}

impl<T: SimdUnsignedInteger> LazyReduceAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn lazy_reduce_assign(self, value: &mut T::SimdT) {
        *value = self.lazy_reduce(*value);
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMul<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn lazy_reduce_mul(self, a: T::SimdT, b: T::SimdT) -> Self::Output {
        let (lo, hi) = a.widening_mul(b);
        self.lazy_reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMulAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_assign(self, a: &mut T::SimdT, b: T::SimdT) {
        let (lo, hi) = a.widening_mul(b);
        *a = self.lazy_reduce_wide(lo, hi);
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMulAdd<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn lazy_reduce_mul_add(self, a: T::SimdT, b: T::SimdT, c: T::SimdT) -> Self::Output {
        let (lo, hi) = a.carrying_mul(b, c);
        self.lazy_reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> LazyReduceMulAddAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn lazy_reduce_mul_add_assign(self, a: &mut T::SimdT, b: T::SimdT, c: T::SimdT) {
        let (lo, hi) = a.carrying_mul(b, c);
        *a = self.lazy_reduce_wide(lo, hi);
    }
}

impl<T: SimdUnsignedInteger> Reduce<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn reduce(self, value: T::SimdT) -> Self::Output {
        compact::simd::reduce_once::<T>(self.value, self.lazy_reduce(value))
    }
}

impl<T: SimdUnsignedInteger> ReduceAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn reduce_assign(self, value: &mut T::SimdT) {
        *value = self.reduce(*value);
    }
}

impl<T: SimdUnsignedInteger> ReduceMul<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn reduce_mul(self, a: T::SimdT, b: T::SimdT) -> Self::Output {
        let (lo, hi) = a.widening_mul(b);
        self.reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> ReduceMulAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn reduce_mul_assign(self, a: &mut T::SimdT, b: T::SimdT) {
        let (lo, hi) = a.widening_mul(b);
        *a = self.reduce_wide(lo, hi);
    }
}

impl<T: SimdUnsignedInteger> ReduceMulAdd<T::SimdT> for SimdBarrettModulus<T> {
    type Output = T::SimdT;

    #[inline]
    fn reduce_mul_add(self, a: T::SimdT, b: T::SimdT, c: T::SimdT) -> Self::Output {
        let (lo, hi) = a.carrying_mul(b, c);
        self.reduce_wide(lo, hi)
    }
}

impl<T: SimdUnsignedInteger> ReduceMulAddAssign<T::SimdT> for SimdBarrettModulus<T> {
    #[inline]
    fn reduce_mul_add_assign(self, a: &mut T::SimdT, b: T::SimdT, c: T::SimdT) {
        let (lo, hi) = a.carrying_mul(b, c);
        *a = self.reduce_wide(lo, hi);
    }
}

// Each outer chunk contains `K = DOT_PRODUCT_INNER_CHUNK` SIMD vectors. Every
// lane accumulates `K` widening products, is reduced, and is then added to the
// running lane-wise residue. The final horizontal sum and scalar tail complete
// the dot product.
//
// Accumulator safety: `m < 2^(BITS - 2)` and each input is less than `m`, so
// each product is less than `2^(2 * BITS - 4)`. With `K = 16`, their sum is
// less than `2^(2 * BITS)` and fits in the two-limb accumulator.
/// Computes the dot product of `a` and `b` modulo `modulus` using SIMD chunks.
///
/// # Correctness
///
/// Every input element must be less than the modulus.
///
/// # Panics
///
/// Panics if `a` and `b` have different lengths.
#[inline]
pub fn simd_reduce_dot_product<T: SimdUnsignedInteger, M>(modulus: M, a: &[T], b: &[T]) -> T
where
    M: Copy + Into<SimdBarrettModulus<T>> + ReduceAdd<T, Output = T> + Reduce<[T; 2], Output = T>,
{
    assert_eq!(a.len(), b.len(), "reduce_dot_product: length mismatch");

    let k = compact::DOT_PRODUCT_INNER_CHUNK;
    let outer = k * T::LANE_COUNT;

    let sm: SimdBarrettModulus<T> = modulus.into();
    let mv = sm.value;

    let mut total_acc = T::SimdT::splat(T::ZERO);

    let mut a_outer = a.chunks_exact(outer);
    let mut b_outer = b.chunks_exact(outer);

    for (a_chunk, b_chunk) in (&mut a_outer).zip(&mut b_outer) {
        // An outer chunk contains exactly `K` full SIMD vectors.
        let (a_lanes, _) = T::simd_as_chunks(a_chunk);
        let (b_lanes, _) = T::simd_as_chunks(b_chunk);
        let mut c = [T::SimdT::splat(T::ZERO); 2];
        for (a_n, b_n) in a_lanes.iter().zip(b_lanes) {
            let av = T::SimdT::from_array(*a_n);
            let bv = T::SimdT::from_array(*b_n);
            compact::simd::multiply_add::<T>(&mut c, av, bv);
        }
        let r = compact::simd::reduce_once::<T>(mv, sm.lazy_reduce_wide(c[0], c[1]));
        total_acc = compact::simd::reduce_add::<T>(mv, total_acc, r);
    }

    let lanes = total_acc.to_array();
    let mut result = T::ZERO;
    for v in lanes {
        result = modulus.reduce_add(result, v);
    }

    let tail_result =
        compact::slice::reduce_dot_product(modulus, a_outer.remainder(), b_outer.remainder());

    modulus.reduce_add(result, tail_result)
}
