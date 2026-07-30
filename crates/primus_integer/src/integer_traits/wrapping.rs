use core::num::Wrapping;
use core::ops::{Add, Mul, Neg, Shl, Shr, Sub};

macro_rules! impl_wrapping {
    ($trait_name:ident, $method:ident, $T:ty) => {
        impl $trait_name for $T {
            #[inline]
            fn $method(self, v: Self) -> Self {
                <$T>::$method(self, v)
            }
        }
    };
    ($trait_name:ident, $method:ident, $T:ty, $rhs:ty) => {
        impl $trait_name<$rhs> for $T {
            #[inline]
            fn $method(self, v: $rhs) -> Self {
                <$T>::$method(self, v)
            }
        }
    };
}

/// Performs addition that wraps around on overflow.
pub trait WrappingAdd: Sized + Copy + Add<Self, Output = Self> {
    /// Wrapping (modular) addition. Computes `self + other`, wrapping around at the boundary of
    /// the type.
    #[must_use]
    fn wrapping_add(self, v: Self) -> Self;
}

impl_wrapping!(WrappingAdd, wrapping_add, u8);
impl_wrapping!(WrappingAdd, wrapping_add, u16);
impl_wrapping!(WrappingAdd, wrapping_add, u32);
impl_wrapping!(WrappingAdd, wrapping_add, u64);
impl_wrapping!(WrappingAdd, wrapping_add, usize);
impl_wrapping!(WrappingAdd, wrapping_add, u128);

impl_wrapping!(WrappingAdd, wrapping_add, i8);
impl_wrapping!(WrappingAdd, wrapping_add, i16);
impl_wrapping!(WrappingAdd, wrapping_add, i32);
impl_wrapping!(WrappingAdd, wrapping_add, i64);
impl_wrapping!(WrappingAdd, wrapping_add, isize);
impl_wrapping!(WrappingAdd, wrapping_add, i128);

/// Performs subtraction that wraps around on overflow.
pub trait WrappingSub: Sized + Copy + Sub<Self, Output = Self> {
    /// Wrapping (modular) subtraction. Computes `self - other`, wrapping around at the boundary
    /// of the type.
    #[must_use]
    fn wrapping_sub(self, v: Self) -> Self;
}

impl_wrapping!(WrappingSub, wrapping_sub, u8);
impl_wrapping!(WrappingSub, wrapping_sub, u16);
impl_wrapping!(WrappingSub, wrapping_sub, u32);
impl_wrapping!(WrappingSub, wrapping_sub, u64);
impl_wrapping!(WrappingSub, wrapping_sub, usize);
impl_wrapping!(WrappingSub, wrapping_sub, u128);

impl_wrapping!(WrappingSub, wrapping_sub, i8);
impl_wrapping!(WrappingSub, wrapping_sub, i16);
impl_wrapping!(WrappingSub, wrapping_sub, i32);
impl_wrapping!(WrappingSub, wrapping_sub, i64);
impl_wrapping!(WrappingSub, wrapping_sub, isize);
impl_wrapping!(WrappingSub, wrapping_sub, i128);

/// Performs multiplication that wraps around on overflow.
pub trait WrappingMul: Sized + Copy + Mul<Self, Output = Self> {
    /// Wrapping (modular) multiplication. Computes `self * other`, wrapping around at the boundary
    /// of the type.
    #[must_use]
    fn wrapping_mul(self, v: Self) -> Self;
}

impl_wrapping!(WrappingMul, wrapping_mul, u8);
impl_wrapping!(WrappingMul, wrapping_mul, u16);
impl_wrapping!(WrappingMul, wrapping_mul, u32);
impl_wrapping!(WrappingMul, wrapping_mul, u64);
impl_wrapping!(WrappingMul, wrapping_mul, usize);
impl_wrapping!(WrappingMul, wrapping_mul, u128);

impl_wrapping!(WrappingMul, wrapping_mul, i8);
impl_wrapping!(WrappingMul, wrapping_mul, i16);
impl_wrapping!(WrappingMul, wrapping_mul, i32);
impl_wrapping!(WrappingMul, wrapping_mul, i64);
impl_wrapping!(WrappingMul, wrapping_mul, isize);
impl_wrapping!(WrappingMul, wrapping_mul, i128);

macro_rules! impl_wrapping_unary {
    ($trait_name:ident, $method:ident, $T:ty) => {
        impl $trait_name for $T {
            #[inline]
            fn $method(self) -> $T {
                <$T>::$method(self)
            }
        }
    };
}

/// Performs a negation that does not panic.
pub trait WrappingNeg: Sized + Copy {
    /// Wrapping (modular) negation. Computes `-self`,
    /// wrapping around at the boundary of the type.
    ///
    /// Since unsigned types do not have negative equivalents
    /// all applications of this function will wrap (except for `-0`).
    /// For values smaller than the corresponding signed type's maximum
    /// the result is the same as casting the corresponding signed value.
    /// Any larger values are equivalent to `MAX + 1 - (val - MAX - 1)` where
    /// `MAX` is the corresponding signed type's maximum.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::WrappingNeg;
    ///
    /// assert_eq!(WrappingNeg::wrapping_neg(100i8), -100);
    /// assert_eq!(WrappingNeg::wrapping_neg(-100i8), 100);
    /// assert_eq!(WrappingNeg::wrapping_neg(-128i8), -128); // wrapped!
    /// ```
    #[must_use]
    fn wrapping_neg(self) -> Self;
}

impl_wrapping_unary!(WrappingNeg, wrapping_neg, u8);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u16);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u32);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u64);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, usize);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, u128);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i8);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i16);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i32);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i64);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, isize);
impl_wrapping_unary!(WrappingNeg, wrapping_neg, i128);

macro_rules! impl_wrapping_shift {
    ($trait_name:ident, $method:ident, $T:ty) => {
        impl $trait_name for $T {
            #[inline]
            fn $method(self, rhs: u32) -> $T {
                <$T>::$method(self, rhs)
            }
        }
    };
}

/// Performs a left shift that does not panic.
pub trait WrappingShl: Sized + Copy + Shl<usize, Output = Self> {
    /// Panic-free bitwise shift-left; yields `self << mask(rhs)`,
    /// where `mask` removes any high order bits of `rhs` that would
    /// cause the shift to exceed the bitwidth of the type.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::WrappingShl;
    ///
    /// let x: u16 = 0x0001;
    ///
    /// assert_eq!(WrappingShl::wrapping_shl(x, 0),  0x0001);
    /// assert_eq!(WrappingShl::wrapping_shl(x, 1),  0x0002);
    /// assert_eq!(WrappingShl::wrapping_shl(x, 15), 0x8000);
    /// assert_eq!(WrappingShl::wrapping_shl(x, 16), 0x0001);
    /// ```
    #[must_use]
    fn wrapping_shl(self, rhs: u32) -> Self;
}

impl_wrapping_shift!(WrappingShl, wrapping_shl, u8);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u16);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u32);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u64);
impl_wrapping_shift!(WrappingShl, wrapping_shl, usize);
impl_wrapping_shift!(WrappingShl, wrapping_shl, u128);

impl_wrapping_shift!(WrappingShl, wrapping_shl, i8);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i16);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i32);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i64);
impl_wrapping_shift!(WrappingShl, wrapping_shl, isize);
impl_wrapping_shift!(WrappingShl, wrapping_shl, i128);

/// Performs a right shift that does not panic.
pub trait WrappingShr: Sized + Copy + Shr<usize, Output = Self> {
    /// Panic-free bitwise shift-right; yields `self >> mask(rhs)`,
    /// where `mask` removes any high order bits of `rhs` that would
    /// cause the shift to exceed the bitwidth of the type.
    ///
    /// # Examples
    ///
    /// ```
    /// use primus_integer::WrappingShr;
    ///
    /// let x: u16 = 0x8000;
    ///
    /// assert_eq!(WrappingShr::wrapping_shr(x, 0),  0x8000);
    /// assert_eq!(WrappingShr::wrapping_shr(x, 1),  0x4000);
    /// assert_eq!(WrappingShr::wrapping_shr(x, 15), 0x0001);
    /// assert_eq!(WrappingShr::wrapping_shr(x, 16), 0x8000);
    /// ```
    #[must_use]
    fn wrapping_shr(self, rhs: u32) -> Self;
}

impl_wrapping_shift!(WrappingShr, wrapping_shr, u8);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u16);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u32);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u64);
impl_wrapping_shift!(WrappingShr, wrapping_shr, usize);
impl_wrapping_shift!(WrappingShr, wrapping_shr, u128);

impl_wrapping_shift!(WrappingShr, wrapping_shr, i8);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i16);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i32);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i64);
impl_wrapping_shift!(WrappingShr, wrapping_shr, isize);
impl_wrapping_shift!(WrappingShr, wrapping_shr, i128);

// Forward our wrapping traits through std's Wrapping<T> so that generic
// code bounded on WrappingAdd / WrappingSub / … can also operate on
// std::num::Wrapping<T> values.
impl<T: WrappingAdd> WrappingAdd for Wrapping<T>
where
    Wrapping<T>: Add<Output = Wrapping<T>>,
{
    fn wrapping_add(self, v: Self) -> Self {
        Wrapping(self.0.wrapping_add(v.0))
    }
}
impl<T: WrappingSub> WrappingSub for Wrapping<T>
where
    Wrapping<T>: Sub<Output = Wrapping<T>>,
{
    fn wrapping_sub(self, v: Self) -> Self {
        Wrapping(self.0.wrapping_sub(v.0))
    }
}
impl<T: WrappingMul> WrappingMul for Wrapping<T>
where
    Wrapping<T>: Mul<Output = Wrapping<T>>,
{
    fn wrapping_mul(self, v: Self) -> Self {
        Wrapping(self.0.wrapping_mul(v.0))
    }
}
impl<T: WrappingNeg> WrappingNeg for Wrapping<T>
where
    Wrapping<T>: Neg<Output = Wrapping<T>>,
{
    fn wrapping_neg(self) -> Self {
        Wrapping(self.0.wrapping_neg())
    }
}
impl<T: WrappingShl> WrappingShl for Wrapping<T>
where
    Wrapping<T>: Shl<usize, Output = Wrapping<T>>,
{
    fn wrapping_shl(self, rhs: u32) -> Self {
        Wrapping(self.0.wrapping_shl(rhs))
    }
}
impl<T: WrappingShr> WrappingShr for Wrapping<T>
where
    Wrapping<T>: Shr<usize, Output = Wrapping<T>>,
{
    fn wrapping_shr(self, rhs: u32) -> Self {
        Wrapping(self.0.wrapping_shr(rhs))
    }
}
