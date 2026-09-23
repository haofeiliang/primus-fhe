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
            ($t:ty, $kernel:ident) => {
                if TypeId::of::<T>() == TypeId::of::<$t>() {
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
                    if is_x86_feature_detected!("avx512f") {
                        // SAFETY: CPU feature checked; slices have equal lengths.
                        unsafe {
                            avx512::$kernel(modulus, acc, lhs, rhs);
                        }
                        return true;
                    }
                }
            };
        }
        dispatch!(u32, add_mul_u32);
        // The existing portable-SIMD u64 kernel wins in complete PBS.
        // Keep it when `simd` is enabled; stable builds use this native kernel.
        if !cfg!(feature = "simd") {
            dispatch!(u64, add_mul_u64);
        }
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

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn wide(a: __m512i, b: __m512i) -> (__m512i, __m512i) {
        let mask = _mm512_set1_epi64(0xffff_ffff);
        let p00 = _mm512_mul_epu32(a, b);
        let p01 = _mm512_mul_epu32(a, _mm512_srli_epi64::<32>(b));
        let p10 = _mm512_mul_epu32(_mm512_srli_epi64::<32>(a), b);
        let p11 = _mm512_mul_epu32(_mm512_srli_epi64::<32>(a), _mm512_srli_epi64::<32>(b));
        let middle = _mm512_add_epi64(
            _mm512_srli_epi64::<32>(p00),
            _mm512_add_epi64(_mm512_and_si512(p01, mask), _mm512_and_si512(p10, mask)),
        );
        let lo = _mm512_or_si512(_mm512_and_si512(p00, mask), _mm512_slli_epi64::<32>(middle));
        let hi = _mm512_add_epi64(
            p11,
            _mm512_add_epi64(
                _mm512_srli_epi64::<32>(p01),
                _mm512_add_epi64(
                    _mm512_srli_epi64::<32>(p10),
                    _mm512_srli_epi64::<32>(middle),
                ),
            ),
        );
        (lo, hi)
    }

    #[inline]
    #[target_feature(enable = "avx512f")]
    unsafe fn mullo(a: __m512i, b: __m512i) -> __m512i {
        _mm512_add_epi64(
            _mm512_mul_epu32(a, b),
            _mm512_slli_epi64::<32>(_mm512_add_epi64(
                _mm512_mul_epu32(a, _mm512_srli_epi64::<32>(b)),
                _mm512_mul_epu32(_mm512_srli_epi64::<32>(a), b),
            )),
        )
    }

    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn add_mul_u64(
        modulus: BarrettModulus<u64>,
        acc: &mut [u64],
        lhs: &[u64],
        rhs: &[u64],
    ) {
        debug_assert_eq!(acc.len(), lhs.len());
        debug_assert_eq!(acc.len(), rhs.len());
        // SAFETY: feature is supplied by caller; equal lengths and the
        // complete-chunk bound protect all unaligned vector accesses.
        unsafe {
            let q = _mm512_set1_epi64(modulus.value() as i64);
            let [r0, r1] = modulus.ratio().map(|x| _mm512_set1_epi64(x as i64));
            let end = acc.len() / 8 * 8;
            for i in (0..end).step_by(8) {
                let a = _mm512_loadu_si512(lhs.as_ptr().add(i).cast());
                let b = _mm512_loadu_si512(rhs.as_ptr().add(i).cast());
                let c = _mm512_loadu_si512(acc.as_ptr().add(i).cast());
                let (product, high) = wide(a, b);
                let lo = _mm512_add_epi64(product, c);
                let hi = _mm512_add_epi64(high, carry(product, lo));
                // Match scalar lazy_reduce_wide, including both carries.
                let ah = wide(lo, r0).1;
                let (bl0, bh0) = wide(lo, r1);
                let bl = _mm512_add_epi64(bl0, ah);
                let bh = _mm512_add_epi64(bh0, carry(bl0, bl));
                let (cl, ch) = wide(hi, r0);
                let bch = _mm512_add_epi64(
                    _mm512_add_epi64(bh, ch),
                    carry(bl, _mm512_add_epi64(bl, cl)),
                );
                let quotient = _mm512_add_epi64(mullo(hi, r1), bch);
                let value = normalize(_mm512_sub_epi64(lo, mullo(quotient, q)), q);
                _mm512_storeu_si512(acc.as_mut_ptr().add(i).cast(), value);
            }
            for ((c, &a), &b) in acc[end..].iter_mut().zip(&lhs[end..]).zip(&rhs[end..]) {
                *c = modulus.reduce_mul_add(a, b, *c);
            }
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
    unsafe fn carry(a: __m512i, sum: __m512i) -> __m512i {
        _mm512_maskz_mov_epi64(_mm512_cmplt_epu64_mask(sum, a), _mm512_set1_epi64(1))
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
            ($t:ty, $kernel:ident, $qs:expr) => {
                for q in $qs {
                    let modulus = BarrettModulus::<$t>::new(q);
                    type Kernel = unsafe fn(BarrettModulus<$t>, &mut [$t], &[$t], &[$t]);
                    let mut kernels: Vec<Kernel> = vec![BarrettModulus::<$t>::reduce_add_mul_slice_assign];
                    if is_x86_feature_detected!("avx512f") { kernels.push(avx512::$kernel); }
                    for len in [0, 1, 3, 4, 7, 8, 15, 31, 32, 33, 1025] {
                        let mut state = 42u64;
                        let mut sample = || {
                            state ^= state << 13;
                            state ^= state >> 7;
                            state ^= state << 17;
                            (state % u64::from(q)) as $t
                        };
                        let lhs: Vec<_> = (0..len).map(|i| if i % 3 == 0 {q - 1} else {sample()}).collect();
                        let rhs: Vec<_> = (0..len).map(|i| if i % 3 == 0 {q - 1} else {sample()}).collect();
                        let initial: Vec<_> = (0..len).map(|i| if i % 3 == 0 {q - 1} else {sample()}).collect();
                        let expected: Vec<_> = lhs.iter().zip(&rhs).zip(&initial).map(|((&a,&b),&c)|
                            ((u128::from(a) * u128::from(b) + u128::from(c)) % u128::from(q)) as $t).collect();
                        for kernel in &kernels {
                            // Offset storage exercises unaligned loads and guards both ends.
                            let mut actual = vec![<$t>::MAX; len + 2];
                            actual[1..len+1].copy_from_slice(&initial);
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
        check!(u32, add_mul_u32, [2, 3, 97, 132_120_577, (1 << 30) - 1]);
        check!(
            u64,
            add_mul_u64,
            [
                2,
                3,
                97,
                1_125_899_906_826_241,
                (1 << 50) + 27,
                (1 << 62) - 1
            ]
        );
    }
}
