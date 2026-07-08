//! SIMD-accelerated pointwise arithmetic on split `[re | im]` f64 layout.
//!
//! Runtime dispatch selects the widest available ISA: AVX-512F → AVX2+FMA →
//! scalar fallback.  All unsafe blocks are self-contained and the public API
//! is safe.
#![allow(unsafe_op_in_unsafe_fn)]

// ---------------------------------------------------------------------------
// Public dispatchers
// ---------------------------------------------------------------------------

/// `acc_re/im += lhs_re/im * rhs_re/im` (complex fused multiply-add, `m` complex values).
///
/// This is the hot path for TFHE external product accumulation.
#[inline]
pub fn add_mul_assign(acc: &mut [f64], lhs: &[f64], rhs: &[f64], m: usize) {
    debug_assert_eq!(acc.len(), 2 * m);
    debug_assert_eq!(lhs.len(), 2 * m);
    debug_assert_eq!(rhs.len(), 2 * m);
    let (acc_re, acc_im) = acc.split_at_mut(m);
    let (l_re, l_im) = lhs.split_at(m);
    let (r_re, r_im) = rhs.split_at(m);

    #[cfg(target_arch = "x86_64")]
    {
        if *super::constants::HAS_AVX512F {
            unsafe {
                avx512::add_mul_assign(acc_re, acc_im, l_re, l_im, r_re, r_im, m);
                return;
            }
        }
        if *super::constants::HAS_AVX2_FMA {
            unsafe {
                avx2::add_mul_assign(acc_re, acc_im, l_re, l_im, r_re, r_im, m);
                return;
            }
        }
    }
    add_mul_assign_scalar(acc_re, acc_im, l_re, l_im, r_re, r_im, m);
}

/// `out_re/im = a_re/im * b_re/im` (complex multiply, `m` complex values).
#[inline]
pub fn mul_to(a: &[f64], b: &[f64], out: &mut [f64], m: usize) {
    debug_assert_eq!(a.len(), 2 * m);
    debug_assert_eq!(b.len(), 2 * m);
    debug_assert_eq!(out.len(), 2 * m);
    let (a_re, a_im) = a.split_at(m);
    let (b_re, b_im) = b.split_at(m);
    let (out_re, out_im) = out.split_at_mut(m);

    #[cfg(target_arch = "x86_64")]
    {
        if *super::constants::HAS_AVX512F {
            unsafe {
                avx512::mul_to(a_re, a_im, b_re, b_im, out_re, out_im, m);
                return;
            }
        }
        if *super::constants::HAS_AVX2_FMA {
            unsafe {
                avx2::mul_to(a_re, a_im, b_re, b_im, out_re, out_im, m);
                return;
            }
        }
    }
    mul_to_scalar(a_re, a_im, b_re, b_im, out_re, out_im, m);
}

/// `arr[..2*m] = -arr[..2*m]` (negation, `m` complex values).
#[inline]
pub fn neg_assign(arr: &mut [f64], m: usize) {
    debug_assert_eq!(arr.len(), 2 * m);
    #[cfg(target_arch = "x86_64")]
    {
        if *super::constants::HAS_AVX512F {
            unsafe {
                avx512::neg_assign(arr, 2 * m);
                return;
            }
        }
        if is_x86_feature_detected!("avx2") {
            unsafe {
                avx2::neg_assign(arr, 2 * m);
                return;
            }
        }
    }
    for x in &mut arr[..2 * m] {
        *x = -*x;
    }
}

/// `acc[..2*m] += rhs[..2*m]` (element-wise add).
#[inline]
pub fn add_assign(acc: &mut [f64], rhs: &[f64], m: usize) {
    let len = 2 * m;
    debug_assert_eq!(acc.len(), len);
    debug_assert_eq!(rhs.len(), len);
    #[cfg(target_arch = "x86_64")]
    {
        if *super::constants::HAS_AVX512F {
            unsafe {
                avx512::add_assign(&mut acc[..len], &rhs[..len], len);
                return;
            }
        }
        if is_x86_feature_detected!("avx2") {
            unsafe {
                avx2::add_assign(&mut acc[..len], &rhs[..len], len);
                return;
            }
        }
    }
    for (a, &b) in acc[..len].iter_mut().zip(&rhs[..len]) {
        *a += b;
    }
}

/// `acc[..2*m] -= rhs[..2*m]` (element-wise sub).
#[inline]
pub fn sub_assign(acc: &mut [f64], rhs: &[f64], m: usize) {
    let len = 2 * m;
    debug_assert_eq!(acc.len(), len);
    debug_assert_eq!(rhs.len(), len);
    #[cfg(target_arch = "x86_64")]
    {
        if *super::constants::HAS_AVX512F {
            unsafe {
                avx512::sub_assign(&mut acc[..len], &rhs[..len], len);
                return;
            }
        }
        if is_x86_feature_detected!("avx2") {
            unsafe {
                avx2::sub_assign(&mut acc[..len], &rhs[..len], len);
                return;
            }
        }
    }
    for (a, &b) in acc[..len].iter_mut().zip(&rhs[..len]) {
        *a -= b;
    }
}

// ---------------------------------------------------------------------------
// Scalar fallbacks
// ---------------------------------------------------------------------------

fn add_mul_assign_scalar(
    acc_re: &mut [f64],
    acc_im: &mut [f64],
    l_re: &[f64],
    l_im: &[f64],
    r_re: &[f64],
    r_im: &[f64],
    m: usize,
) {
    for i in 0..m {
        acc_re[i] += l_re[i] * r_re[i] - l_im[i] * r_im[i];
        acc_im[i] += l_re[i] * r_im[i] + l_im[i] * r_re[i];
    }
}

fn mul_to_scalar(
    a_re: &[f64],
    a_im: &[f64],
    b_re: &[f64],
    b_im: &[f64],
    out_re: &mut [f64],
    out_im: &mut [f64],
    m: usize,
) {
    for i in 0..m {
        out_re[i] = a_re[i] * b_re[i] - a_im[i] * b_im[i];
        out_im[i] = a_re[i] * b_im[i] + a_im[i] * b_re[i];
    }
}

// ---------------------------------------------------------------------------
// AVX2+FMA (256-bit, 4 complex values / iteration)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub(crate) mod avx2 {
    use std::arch::x86_64::*;

    /// 4-wide complex FMA: acc += lhs * rhs.
    #[target_feature(enable = "avx2,fma")]
    pub unsafe fn add_mul_assign(
        acc_re: &mut [f64],
        acc_im: &mut [f64],
        l_re: &[f64],
        l_im: &[f64],
        r_re: &[f64],
        r_im: &[f64],
        m: usize,
    ) {
        let mut i = 0usize;
        while i + 3 < m {
            let lre = _mm256_loadu_pd(l_re.as_ptr().add(i));
            let lim = _mm256_loadu_pd(l_im.as_ptr().add(i));
            let rre = _mm256_loadu_pd(r_re.as_ptr().add(i));
            let rim = _mm256_loadu_pd(r_im.as_ptr().add(i));
            let acc_re_v = _mm256_loadu_pd(acc_re.as_ptr().add(i));
            let acc_im_v = _mm256_loadu_pd(acc_im.as_ptr().add(i));

            // t_re = l_re * r_re - l_im * r_im
            // Use fnmadd: dst = -(a*b) + c  →  -(l_im*r_im) + l_re*r_re
            let t_re = _mm256_fnmadd_pd(lim, rim, _mm256_mul_pd(lre, rre));
            // t_im = l_re * r_im + l_im * r_re
            let t_im = _mm256_fmadd_pd(lim, rre, _mm256_mul_pd(lre, rim));

            _mm256_storeu_pd(acc_re.as_mut_ptr().add(i), _mm256_add_pd(acc_re_v, t_re));
            _mm256_storeu_pd(acc_im.as_mut_ptr().add(i), _mm256_add_pd(acc_im_v, t_im));
            i += 4;
        }
        // scalar tail
        for j in i..m {
            *acc_re.get_unchecked_mut(j) += *l_re.get_unchecked(j) * *r_re.get_unchecked(j)
                - *l_im.get_unchecked(j) * *r_im.get_unchecked(j);
            *acc_im.get_unchecked_mut(j) += *l_re.get_unchecked(j) * *r_im.get_unchecked(j)
                + *l_im.get_unchecked(j) * *r_re.get_unchecked(j);
        }
    }

    /// 4-wide complex multiply: out = a * b.
    #[target_feature(enable = "avx2,fma")]
    pub unsafe fn mul_to(
        a_re: &[f64],
        a_im: &[f64],
        b_re: &[f64],
        b_im: &[f64],
        out_re: &mut [f64],
        out_im: &mut [f64],
        m: usize,
    ) {
        let mut i = 0usize;
        while i + 3 < m {
            let are = _mm256_loadu_pd(a_re.as_ptr().add(i));
            let aim = _mm256_loadu_pd(a_im.as_ptr().add(i));
            let bre = _mm256_loadu_pd(b_re.as_ptr().add(i));
            let bim = _mm256_loadu_pd(b_im.as_ptr().add(i));

            // out_re = a_re * b_re - a_im * b_im
            let out_re_v = _mm256_fnmadd_pd(aim, bim, _mm256_mul_pd(are, bre));
            // out_im = a_re * b_im + a_im * b_re
            let out_im_v = _mm256_fmadd_pd(aim, bre, _mm256_mul_pd(are, bim));

            _mm256_storeu_pd(out_re.as_mut_ptr().add(i), out_re_v);
            _mm256_storeu_pd(out_im.as_mut_ptr().add(i), out_im_v);
            i += 4;
        }
        for j in i..m {
            *out_re.get_unchecked_mut(j) = *a_re.get_unchecked(j) * *b_re.get_unchecked(j)
                - *a_im.get_unchecked(j) * *b_im.get_unchecked(j);
            *out_im.get_unchecked_mut(j) = *a_re.get_unchecked(j) * *b_im.get_unchecked(j)
                + *a_im.get_unchecked(j) * *b_re.get_unchecked(j);
        }
    }

    /// 4-wide element-wise negation.
    #[target_feature(enable = "avx2")]
    pub unsafe fn neg_assign(arr: &mut [f64], len: usize) {
        let sign = _mm256_set1_pd(-0.0f64);
        let mut i = 0usize;
        while i + 3 < len {
            let v = _mm256_loadu_pd(arr.as_ptr().add(i));
            _mm256_storeu_pd(arr.as_mut_ptr().add(i), _mm256_xor_pd(v, sign));
            i += 4;
        }
        for j in i..len {
            *arr.get_unchecked_mut(j) = -*arr.get_unchecked(j);
        }
    }

    /// 4-wide element-wise add.
    #[target_feature(enable = "avx2")]
    pub unsafe fn add_assign(acc: &mut [f64], rhs: &[f64], len: usize) {
        let mut i = 0usize;
        while i + 3 < len {
            let a = _mm256_loadu_pd(acc.as_ptr().add(i));
            let b = _mm256_loadu_pd(rhs.as_ptr().add(i));
            _mm256_storeu_pd(acc.as_mut_ptr().add(i), _mm256_add_pd(a, b));
            i += 4;
        }
        for j in i..len {
            *acc.get_unchecked_mut(j) += *rhs.get_unchecked(j);
        }
    }

    /// 4-wide element-wise sub.
    #[target_feature(enable = "avx2")]
    pub unsafe fn sub_assign(acc: &mut [f64], rhs: &[f64], len: usize) {
        let mut i = 0usize;
        while i + 3 < len {
            let a = _mm256_loadu_pd(acc.as_ptr().add(i));
            let b = _mm256_loadu_pd(rhs.as_ptr().add(i));
            _mm256_storeu_pd(acc.as_mut_ptr().add(i), _mm256_sub_pd(a, b));
            i += 4;
        }
        for j in i..len {
            *acc.get_unchecked_mut(j) -= *rhs.get_unchecked(j);
        }
    }
}

// ---------------------------------------------------------------------------
// AVX-512F (512-bit, 8 complex values / iteration)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
pub(crate) mod avx512 {
    use std::arch::x86_64::*;

    /// 8-wide complex FMA.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn add_mul_assign(
        acc_re: &mut [f64],
        acc_im: &mut [f64],
        l_re: &[f64],
        l_im: &[f64],
        r_re: &[f64],
        r_im: &[f64],
        m: usize,
    ) {
        let mut i = 0usize;
        while i + 7 < m {
            let lre = _mm512_loadu_pd(l_re.as_ptr().add(i));
            let lim = _mm512_loadu_pd(l_im.as_ptr().add(i));
            let rre = _mm512_loadu_pd(r_re.as_ptr().add(i));
            let rim = _mm512_loadu_pd(r_im.as_ptr().add(i));
            let acc_re_v = _mm512_loadu_pd(acc_re.as_ptr().add(i));
            let acc_im_v = _mm512_loadu_pd(acc_im.as_ptr().add(i));

            let t_re = _mm512_fnmadd_pd(lim, rim, _mm512_mul_pd(lre, rre));
            let t_im = _mm512_fmadd_pd(lim, rre, _mm512_mul_pd(lre, rim));

            _mm512_storeu_pd(acc_re.as_mut_ptr().add(i), _mm512_add_pd(acc_re_v, t_re));
            _mm512_storeu_pd(acc_im.as_mut_ptr().add(i), _mm512_add_pd(acc_im_v, t_im));
            i += 8;
        }
        for j in i..m {
            *acc_re.get_unchecked_mut(j) += *l_re.get_unchecked(j) * *r_re.get_unchecked(j)
                - *l_im.get_unchecked(j) * *r_im.get_unchecked(j);
            *acc_im.get_unchecked_mut(j) += *l_re.get_unchecked(j) * *r_im.get_unchecked(j)
                + *l_im.get_unchecked(j) * *r_re.get_unchecked(j);
        }
    }

    /// 8-wide complex multiply.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn mul_to(
        a_re: &[f64],
        a_im: &[f64],
        b_re: &[f64],
        b_im: &[f64],
        out_re: &mut [f64],
        out_im: &mut [f64],
        m: usize,
    ) {
        let mut i = 0usize;
        while i + 7 < m {
            let are = _mm512_loadu_pd(a_re.as_ptr().add(i));
            let aim = _mm512_loadu_pd(a_im.as_ptr().add(i));
            let bre = _mm512_loadu_pd(b_re.as_ptr().add(i));
            let bim = _mm512_loadu_pd(b_im.as_ptr().add(i));

            let out_re_v = _mm512_fnmadd_pd(aim, bim, _mm512_mul_pd(are, bre));
            let out_im_v = _mm512_fmadd_pd(aim, bre, _mm512_mul_pd(are, bim));

            _mm512_storeu_pd(out_re.as_mut_ptr().add(i), out_re_v);
            _mm512_storeu_pd(out_im.as_mut_ptr().add(i), out_im_v);
            i += 8;
        }
        for j in i..m {
            *out_re.get_unchecked_mut(j) = *a_re.get_unchecked(j) * *b_re.get_unchecked(j)
                - *a_im.get_unchecked(j) * *b_im.get_unchecked(j);
            *out_im.get_unchecked_mut(j) = *a_re.get_unchecked(j) * *b_im.get_unchecked(j)
                + *a_im.get_unchecked(j) * *b_re.get_unchecked(j);
        }
    }

    /// 8-wide element-wise negation.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn neg_assign(arr: &mut [f64], len: usize) {
        let sign = _mm512_set1_pd(-0.0f64);
        let mut i = 0usize;
        while i + 7 < len {
            let v = _mm512_loadu_pd(arr.as_ptr().add(i));
            _mm512_storeu_pd(arr.as_mut_ptr().add(i), _mm512_xor_pd(v, sign));
            i += 8;
        }
        for j in i..len {
            *arr.get_unchecked_mut(j) = -*arr.get_unchecked(j);
        }
    }

    /// 8-wide element-wise add.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn add_assign(acc: &mut [f64], rhs: &[f64], len: usize) {
        let mut i = 0usize;
        while i + 7 < len {
            let a = _mm512_loadu_pd(acc.as_ptr().add(i));
            let b = _mm512_loadu_pd(rhs.as_ptr().add(i));
            _mm512_storeu_pd(acc.as_mut_ptr().add(i), _mm512_add_pd(a, b));
            i += 8;
        }
        for j in i..len {
            *acc.get_unchecked_mut(j) += *rhs.get_unchecked(j);
        }
    }

    /// 8-wide element-wise sub.
    #[target_feature(enable = "avx512f")]
    pub unsafe fn sub_assign(acc: &mut [f64], rhs: &[f64], len: usize) {
        let mut i = 0usize;
        while i + 7 < len {
            let a = _mm512_loadu_pd(acc.as_ptr().add(i));
            let b = _mm512_loadu_pd(rhs.as_ptr().add(i));
            _mm512_storeu_pd(acc.as_mut_ptr().add(i), _mm512_sub_pd(a, b));
            i += 8;
        }
        for j in i..len {
            *acc.get_unchecked_mut(j) -= *rhs.get_unchecked(j);
        }
    }
}
