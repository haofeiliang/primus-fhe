//! Integer SIMD for canonical Barrett multiply-add slices.
//!
//! Kernels use the same two-limb reciprocal as the scalar implementation.
//! There is no key-dependent precomputation or change to residue representation.
use super::BarrettModulus;
use primus_integer::FheUint;

#[inline]
pub(super) fn try_add_mul<T: FheUint>(
    modulus: BarrettModulus<T>,
    acc: &mut [T],
    lhs: &[T],
    rhs: &[T],
) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        use std::any::TypeId;
        if acc.len() < 32 {
            return false;
        }
        // Release checks protect all vector loads, even for malformed callers.
        assert_eq!(acc.len(), lhs.len(), "multiply-add length mismatch");
        assert_eq!(acc.len(), rhs.len(), "multiply-add length mismatch");
        macro_rules! dispatch {
            ($t:ty, $kernel:ident, $available:expr) => {
                if TypeId::of::<T>() == TypeId::of::<$t>() && $available {
                    // SAFETY: TypeId proves the exact primitive type, including
                    // size/alignment. Borrowing preserves length and disjointness.
                    let (acc, lhs, rhs) = unsafe {
                        (
                            std::slice::from_raw_parts_mut(
                                acc.as_mut_ptr().cast::<$t>(),
                                acc.len(),
                            ),
                            std::slice::from_raw_parts(lhs.as_ptr().cast::<$t>(), lhs.len()),
                            std::slice::from_raw_parts(rhs.as_ptr().cast::<$t>(), rhs.len()),
                        )
                    };
                    let q: $t = modulus.value().as_into();
                    let ratio = modulus.ratio().map(|x| x.as_into());
                    let modulus = BarrettModulus::<$t>::from_parts(q, ratio);
                    // SAFETY: CPU features checked; slices have equal lengths.
                    unsafe {
                        avx512::$kernel(modulus, acc, lhs, rhs);
                    }
                    return true;
                }
            };
        }
        dispatch!(u32, add_mul_u32, is_x86_feature_detected!("avx512f"));
        dispatch!(
            u64,
            add_mul_u64,
            is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq")
        );
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (modulus, acc, lhs, rhs);
    false
}

#[cfg(target_arch = "x86_64")]
mod avx512 {

    use super::BarrettModulus;
    use primus_reduce::ReduceMulAdd;
    use std::arch::x86_64::*;

    #[inline(always)]
    fn mul_low32(a: u64, b: u64) -> u64 {
        (a & 0xffff_ffff) * (b & 0xffff_ffff)
    }

    // Fuse c into the 32-bit partial products instead of adding it to a
    // completed 128-bit product. Every intermediate sum fits in u64, even
    // for full-width inputs; the returned pair is (low, high) of a*b+c.
    #[inline(always)]
    fn carrying_mul(a: u64, b: u64, c: u64) -> (u64, u64) {
        let p0 = mul_low32(a, b) + (c & 0xffff_ffff);
        let p1 = mul_low32(a, b >> 32) + (c >> 32);
        let p2 = mul_low32(a >> 32, b);
        let p3 = mul_low32(a >> 32, b >> 32);
        let s1 = p1 + (p0 >> 32);
        let s2 = (s1 & 0xffff_ffff) + p2;
        (
            (p0 & 0xffff_ffff) | (s2 << 32),
            p3 + (s1 >> 32) + (s2 >> 32),
        )
    }

    #[inline(always)]
    fn widening_mul_hw(a: u64, b: u64) -> u64 {
        let p00 = mul_low32(a, b);
        let p01 = mul_low32(a, b >> 32);
        let p10 = mul_low32(a >> 32, b);
        let p11 = mul_low32(a >> 32, b >> 32);
        let middle = (p00 >> 32) + (p01 & 0xffff_ffff) + (p10 & 0xffff_ffff);
        p11 + (p01 >> 32) + (p10 >> 32) + (middle >> 32)
    }

    // Keep the arithmetic in the loop's target-feature context: the 32-bit
    // products vectorize to vpmuludq, while the low u64 products use DQ.
    // Expressing the wide products with u128 can introduce scalar multiplies
    // and lane extraction in the vector loop.
    #[target_feature(enable = "avx512f,avx512dq")]
    pub(super) unsafe fn add_mul_u64(
        modulus: BarrettModulus<u64>,
        acc: &mut [u64],
        lhs: &[u64],
        rhs: &[u64],
    ) {
        debug_assert_eq!(acc.len(), lhs.len());
        debug_assert_eq!(acc.len(), rhs.len());
        let q = modulus.value();
        let [r0, r1] = modulus.ratio();
        for ((c, &a), &b) in acc.iter_mut().zip(lhs).zip(rhs) {
            let (lo, hi) = carrying_mul(a, b, *c);
            // Match lazy_reduce_wide, including the carry between the two
            // middle products. Only the low word of the quotient is needed.
            let ah = widening_mul_hw(lo, r0);
            let (bl, bh) = carrying_mul(lo, r1, ah);
            let (cl, ch) = carrying_mul(hi, r0, 0);
            let carry = u64::from(bl.wrapping_add(cl) < bl);
            let quotient = hi
                .wrapping_mul(r1)
                .wrapping_add(bh.wrapping_add(ch).wrapping_add(carry));
            let value = lo.wrapping_sub(quotient.wrapping_mul(q));
            *c = value.min(value.wrapping_sub(q));
        }
    }

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn add_mul_u32(
        modulus: BarrettModulus<u32>,
        acc: &mut [u32],
        lhs: &[u32],
        rhs: &[u32],
    ) {
        debug_assert_eq!(acc.len(), lhs.len());
        debug_assert_eq!(acc.len(), rhs.len());
        // For k=bit_width(q)<=30, x=a*b+c<q^2. Truncated Barrett:
        // qhat = floor(floor(x/2^(k-1))*floor(2^(2k)/q)/2^(k+1)).
        // qhat underestimates floor(x/q) by at most two, so x-qhat*q
        // is in [0,3q). Both factors of the quotient product fit u32:
        // x/2^(k-1)<2^(k+1), and floor(2^(2k)/q)<=2^(k+1).
        // Derive its reciprocal from the existing 64-bit reciprocal;
        // no division, allocation or per-key precomputation is needed.
        unsafe {
            let q = _mm512_set1_epi64(modulus.value() as i64);
            let [low, high] = modulus.ratio();
            let k = u32::BITS - modulus.value().leading_zeros();
            let reciprocal = _mm512_set1_epi64(
                (((u64::from(high) << 32) | u64::from(low)) >> (64 - 2 * k)) as i64,
            );
            let pre_shift = _mm512_set1_epi64(i64::from(k - 1));
            let post_shift = _mm512_set1_epi64(i64::from(k + 1));
            let end = acc.len() / 8 * 8;
            for i in (0..end).step_by(8) {
                let a = load_u32(lhs.as_ptr().add(i));
                let b = load_u32(rhs.as_ptr().add(i));
                let c = load_u32(acc.as_ptr().add(i));
                let product = _mm512_add_epi64(_mm512_mul_epu32(a, b), c);
                let quotient = _mm512_srlv_epi64(
                    _mm512_mul_epu32(_mm512_srlv_epi64(product, pre_shift), reciprocal),
                    post_shift,
                );
                let value = normalize(
                    normalize(_mm512_sub_epi64(product, _mm512_mul_epu32(quotient, q)), q),
                    q,
                );
                store_u32(acc.as_mut_ptr().add(i), value);
            }
            for ((c, &a), &b) in acc[end..].iter_mut().zip(&lhs[end..]).zip(&rhs[end..]) {
                *c = modulus.reduce_mul_add(a, b, *c);
            }
        }
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn normalize(value: __m512i, modulus: __m512i) -> __m512i {
        _mm512_min_epu64(value, _mm512_sub_epi64(value, modulus))
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn load_u32(ptr: *const u32) -> __m512i {
        unsafe { _mm512_cvtepu32_epi64(_mm256_loadu_si256(ptr.cast())) }
    }
    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn store_u32(ptr: *mut u32, value: __m512i) {
        unsafe {
            _mm256_storeu_si256(ptr.cast(), _mm512_cvtepi64_epi32(value));
        }
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use primus_reduce::ReduceMulAddSlice;

    #[test]
    fn native_barrett_kernels_match_wide_remainders() {
        macro_rules! check {
            ($t:ty, $kernel:ident, $available:expr, $qs:expr) => {
                for q in $qs {
                    let modulus = BarrettModulus::<$t>::new(q);
                    type Kernel = unsafe fn(BarrettModulus<$t>, &mut [$t], &[$t], &[$t]);
                    let mut kernels: Vec<Kernel> = vec![BarrettModulus::<$t>::reduce_add_mul_slice_assign];
                    if $available { kernels.push(avx512::$kernel); }
                    for len in [0, 1, 3, 4, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 1025, 4099] {
                        let mut state = 42u64;
                        let mut sample = || {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            (state % u64::from(q)) as $t
                        };
                        let lhs: Vec<_> = (0..len).map(|i| match i % 7 {
                            0 => q - 1, 1 => 0, 2 => 1, _ => sample(),
                        }).collect();
                        let rhs: Vec<_> = (0..len).map(|i| match i % 7 {
                            0 | 2 => q - 1, 1 => 1, _ => sample(),
                        }).collect();
                        let initial: Vec<_> = (0..len).map(|i| match i % 7 {
                            0 | 1 => q - 1, 2 => 0, _ => sample(),
                        }).collect();
                        for kernel in &kernels {
                            // Offset storage exercises unaligned loads and guards both ends.
                            let mut actual = vec![<$t>::MAX; len + 2];
                            actual[1..len+1].copy_from_slice(&initial);
                            let mut expected = initial.clone();
                            for _ in 0..3 {
                                for ((c, &a), &b) in expected.iter_mut().zip(&lhs).zip(&rhs) {
                                    *c = ((u128::from(a) * u128::from(b) + u128::from(*c)) % u128::from(q)) as $t;
                                }
                                // SAFETY: CPU features verified above; canonical inputs and equal lengths.
                                unsafe { kernel(modulus, &mut actual[1..len+1], &lhs, &rhs); }
                                assert_eq!(&actual[1..len+1], expected, "q={q}, len={len}");
                                assert_eq!(actual[0], <$t>::MAX);
                                assert_eq!(actual[len+1], <$t>::MAX);
                            }
                        }
                    }
                }
            }
        }
        check!(
            u32,
            add_mul_u32,
            is_x86_feature_detected!("avx512f"),
            [2, 3, 97, 132_120_577, (1 << 30) - 1]
        );
        check!(
            u64,
            add_mul_u64,
            is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512dq"),
            [
                2,
                3,
                97,
                (1 << 32) - 1,
                (1 << 32) + 15,
                1_125_899_906_826_241,
                (1 << 50) + 27,
                (1 << 62) - 1
            ]
        );
    }
}
