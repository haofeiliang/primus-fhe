use core::fmt::Display;

use primus_integer::FheUint;
use primus_reduce::ReduceOnce;

use crate::integer::{DivRemScalar, UnsignedInteger};

mod ops;
mod slice;

/// SIMD Barrett modulus implementation.
#[cfg(feature = "simd")]
pub mod simd;

#[cfg(feature = "simd")]
pub use simd::{SimdBarrettModulus, simd_reduce_dot_product};

/// A Barrett reduction context for an explicit unsigned-integer modulus.
///
/// For `B = 2^(T::BITS)`, the context stores the modulus and the reciprocal
/// `µ = floor(B² / modulus)`. The modulus must satisfy
/// `1 < modulus < 2^(T::BITS - 2)`; the two spare bits allow 16 products to be
/// accumulated before reduction.
#[derive(Debug, Clone, Copy, Eq)]
pub struct BarrettModulus<T: UnsignedInteger> {
    value: T,
    ratio: [T; 2],
}

impl<T: UnsignedInteger> PartialEq for BarrettModulus<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: UnsignedInteger> BarrettModulus<T> {
    /// Creates a [`BarrettModulus<T>`] for `value`.
    ///
    /// # Panics
    ///
    /// Panics unless `1 < value < 2^(T::BITS - 2)`. For a fallible variant, see
    /// [`try_new`](Self::try_new).
    #[must_use]
    pub fn new(value: T) -> Self {
        assert!(
            value > T::ONE,
            "BarrettModulus::new: modulus must be greater than one"
        );
        let leading_zeros = value.leading_zeros();
        assert!(
            leading_zeros > 1,
            "BarrettModulus::new: modulus must be less than 2^(T::BITS - 2)"
        );
        Self::new_unchecked(value)
    }

    /// Creates a [`BarrettModulus<T>`] without validating `value`.
    ///
    /// # Correctness
    ///
    /// `value` must satisfy `1 < value < 2^(T::BITS - 2)`.
    #[must_use]
    #[inline]
    pub fn new_unchecked(value: T) -> Self {
        let mut quotient = [T::ZERO; 3];
        let _rem = DivRemScalar::div_rem_scalar(&[T::ZERO, T::ZERO, T::ONE], value, &mut quotient);
        Self {
            value,
            ratio: [quotient[0], quotient[1]],
        }
    }

    /// Creates a [`BarrettModulus<T>`] from precomputed parts.
    ///
    /// # Correctness
    ///
    /// `value` must satisfy `1 < value < 2^(T::BITS - 2)`, and `ratio` must be
    /// the little-endian limbs `[low, high]` of `floor(B² / value)`, where
    /// `B = 2^(T::BITS)`.
    #[must_use]
    #[inline]
    pub const fn from_parts(value: T, ratio: [T; 2]) -> Self {
        Self { value, ratio }
    }

    /// Creates a [`BarrettModulus<T>`] when `1 < value < 2^(T::BITS - 2)`, or
    /// returns `None` otherwise.
    #[must_use]
    #[inline]
    pub fn try_new(value: T) -> Option<Self> {
        if value <= T::ONE {
            return None;
        }
        let leading_zeros = value.leading_zeros();
        if leading_zeros < 2 {
            return None;
        }
        Some(Self::new_unchecked(value))
    }

    /// Returns the modulus.
    #[must_use]
    #[inline]
    pub const fn value(&self) -> T {
        self.value
    }

    /// Returns the little-endian limbs `[low, high]` of the precomputed
    /// reciprocal `floor(B² / modulus)`.
    #[must_use]
    #[inline]
    pub const fn ratio(&self) -> [T; 2] {
        self.ratio
    }

    // Lazily reduces the two-limb value `hi * B + lo`.
    #[inline]
    fn lazy_reduce_wide(&self, lo: T, hi: T) -> T {
        //                        ratio[1]  ratio[0]
        //                   *          hi        lo
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //                      +-------------------+
        //                      |         a         |    <-- lo * ratio[0]
        //                      +-------------------+
        //             +------------------+
        //             |        b         |              <-- lo * ratio[1]
        //             +------------------+
        //             +------------------+
        //             |        c         |              <-- hi * ratio[0]
        //             +------------------+
        //   +------------------+
        //   |        d         |                        <-- hi * ratio[1]
        //   +------------------+
        //   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        //             +--------+
        //             |   q₃   |
        //             +--------+

        // Compute the quotient estimate from the upper limbs of
        // `(hi * B + lo) * ratio`, including carries from the lower limbs.
        let ah = lo.widening_mul_hw(self.ratio[0]);

        let b = lo.carrying_mul(self.ratio[1], ah);
        let c = hi.widening_mul(self.ratio[0]);

        let d = hi.wrapping_mul(self.ratio[1]);

        let bch = b.1.carrying_add(c.1, b.0.overflowing_add(c.0).1).0;

        let q = d.wrapping_add(bch);

        // Subtract the estimated multiple modulo `B`.
        lo.wrapping_sub(q.wrapping_mul(self.value))
    }

    /// Reduces a 2-limb value `(hi * B + lo)` modulo this modulus.
    #[must_use]
    #[inline]
    pub fn reduce_wide(&self, lo: T, hi: T) -> T {
        self.reduce_once(self.lazy_reduce_wide(lo, hi))
    }
}

impl<T: UnsignedInteger> Display for BarrettModulus<T> {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl<T: FheUint> primus_reduce::Modulus for BarrettModulus<T> {
    type ValueT = T;

    #[inline]
    fn explicit_value(self) -> Option<Self::ValueT> {
        Some(self.value)
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        self.value - T::ONE
    }
}

impl<T: FheUint> primus_reduce::ExplicitModulus for BarrettModulus<T> {
    #[inline(always)]
    fn value(self) -> Self::ValueT {
        self.value
    }
}
