use core::simd::{Mask, Simd, SimdElement, cmp::SimdPartialOrd, num::SimdInt};

use super::CarryingAdd;

macro_rules! impl_simd_uint_carrying_add {
    ($($T:ty),*) => {
        $(
            impl<const N:usize> CarryingAdd for Simd<$T, N>

            {
                type CarryT = Mask<<$T as SimdElement>::Mask, N>;

                #[inline]
                fn carrying_add(self, rhs: Self, carry: Self::CarryT) -> (Self, Self::CarryT) {
                    let a = self + rhs;
                    let b = a - carry.to_simd().cast();
                    (b, a.simd_lt(self) | b.simd_lt(a))
                }
            }
        )*
    };
}

impl_simd_uint_carrying_add! {u8, u16, u32, u64, usize}
