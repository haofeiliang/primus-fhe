use primus_integer::{FheUint, UnsignedInteger};

mod ops;
mod slice;

#[cfg(feature = "simd")]
mod simd;

/// An explicit, representable power-of-two modulus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PowOf2Modulus<T: UnsignedInteger> {
    /// The reduction mask, equal to the modulus minus one.
    mask: T,
}

impl<T: UnsignedInteger> PowOf2Modulus<T> {
    /// Creates a [`PowOf2Modulus<T>`] for the given modulus.
    ///
    /// # Panics
    ///
    /// Panics unless `value` is a representable power of two greater than one.
    #[inline]
    pub fn new(value: T) -> Self {
        assert!(
            value > T::ONE && value.is_power_of_two(),
            "The value is not a power of 2."
        );
        Self {
            mask: value - T::ONE,
        }
    }

    /// Creates a [`PowOf2Modulus<T>`] from a precomputed reduction mask.
    ///
    /// # Panics
    ///
    /// Panics unless `mask = 2^k - 1` for some `1 ≤ k < T::BITS`.
    #[inline]
    pub fn with_mask(mask: T) -> Self {
        let leading_zeros = mask.leading_zeros();
        assert!(mask.count_zeros() == leading_zeros && !mask.is_zero());
        assert!(
            leading_zeros > 0,
            "NativeModulus<T> supports modulus value such as 2⁸, 2¹⁶, 2³², 2⁶⁴, 2¹²⁸"
        );
        Self { mask }
    }

    /// Returns the modulus.
    #[inline]
    pub fn value(self) -> T {
        self.mask + T::ONE
    }

    /// Returns the reduction mask, which is the modulus minus one.
    #[inline]
    pub const fn mask(self) -> T {
        self.mask
    }
}

impl<T: FheUint> primus_reduce::Modulus for PowOf2Modulus<T> {
    type ValueT = T;

    #[inline]
    fn explicit_value(self) -> Option<Self::ValueT> {
        Some(self.mask + T::ONE)
    }

    #[inline(always)]
    fn minus_one(self) -> Self::ValueT {
        self.mask
    }
}

impl<T: FheUint> primus_reduce::ExplicitModulus for PowOf2Modulus<T> {
    #[inline(always)]
    fn value(self) -> Self::ValueT {
        self.mask + T::ONE
    }
}
