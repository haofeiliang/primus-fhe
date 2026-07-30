use core::simd::{Mask, Simd, SimdElement, cmp::SimdPartialOrd, num::SimdInt};

use super::BorrowingSub;

macro_rules! simd_uint_borrowing_sub_impl {
    ($($T:ty),+) => {
        $(
            impl<const N:usize> BorrowingSub for Simd<$T, N>
            {
                type BorrowT = Mask<<$T as SimdElement>::Mask, N>;

                #[inline]
                fn borrowing_sub(self, rhs: Self, borrow: Self::BorrowT) -> (Self, Self::BorrowT) {
                    let a = self - rhs;
                    let b = a + borrow.to_simd().cast();
                    (b, a.simd_gt(self) | b.simd_gt(a))
                }
            }
        )+
    };
}

simd_uint_borrowing_sub_impl! {u8, u16, u32, u64, usize}
