//! Stockham DIF FFT engine — radix-4 primary, radix-2 tail.
//!
//! Ported and simplified from `tfhe-rs/tfhe-fft`. Provides scalar and AVX2
//! paths with runtime dispatch. No external FFT dependency.

use std::cell::UnsafeCell;
use std::f64::consts::PI;

use num_complex::Complex64;

#[allow(non_camel_case_types)]
pub(crate) type c64 = Complex64;

// ---------------------------------------------------------------------------
// sincospi64 — high-accuracy sin(π·x) and cos(π·x)
// ---------------------------------------------------------------------------

/// High-accuracy `(sin(π·x), cos(π·x))` for `|x| < 2^53`.
#[inline]
pub fn sincospi64(mut a: f64) -> (f64, f64) {
    let az = a * 0.0;
    a = if a.abs() < 9007199254740992.0f64 {
        a
    } else {
        az
    };
    let r = (a + a).round();
    let i = r as i64;
    let t = f64::mul_add(-0.5, r, a);
    let s = t * t;

    let mut r = -1.0369917389758117e-4;
    r = f64::mul_add(r, s, 1.9294935641298806e-3);
    r = f64::mul_add(r, s, -2.5806887942825395e-2);
    r = f64::mul_add(r, s, 2.3533063028328211e-1);
    r = f64::mul_add(r, s, -1.3352627688538006e+0);
    r = f64::mul_add(r, s, 4.0587121264167623e+0);
    r = f64::mul_add(r, s, -4.9348022005446790e+0);
    let mut c = f64::mul_add(r, s, 1.0000000000000000e+0);

    r = 4.6151442520157035e-4;
    r = f64::mul_add(r, s, -7.3700183130883555e-3);
    r = f64::mul_add(r, s, 8.2145868949323936e-2);
    r = f64::mul_add(r, s, -5.9926452893214921e-1);
    r = f64::mul_add(r, s, 2.5501640398732688e+0);
    r = f64::mul_add(r, s, -5.1677127800499516e+0);
    let s = s * t;
    r *= s;
    let mut s = f64::mul_add(t, PI, r);

    if (i & 2) != 0 {
        s = 0.0 - s;
        c = 0.0 - c;
    }
    if (i & 1) != 0 {
        let t = 0.0 - s;
        s = c;
        c = t;
    }
    if a == a.floor() {
        s = az;
    }
    (s, c)
}

// ---------------------------------------------------------------------------
// Twiddle initialization
// ---------------------------------------------------------------------------

/// Initialize radix-`r` twiddle factors for Stockham DIF of size `n`.
///
/// `w` receives `2*n` elements: first `n` are `w_init`, second `n` are `w`.
pub fn init_wt(r: usize, n: usize, w: &mut [c64]) {
    debug_assert!(w.len() == 2 * n);
    if n < r {
        return;
    }
    let nr = n / r;
    let theta = -2.0 / n as f64;
    for wi in w.iter_mut() {
        wi.re = f64::NAN;
        wi.im = f64::NAN;
    }
    for p in 0..nr {
        for k in 1..r {
            let (s, c) = sincospi64(theta * (k * p) as f64);
            let z = c64::new(c, s);
            w[p + k * nr] = z;
            w[n + r * p + k] = z;
        }
    }
}

/// Initialize both forward and inverse twiddle tables for radix-`r`.
pub fn init_wt_pair(r: usize, n: usize) -> (Vec<c64>, Vec<c64>) {
    let mut w_fwd = vec![c64::default(); 2 * n];
    init_wt(r, n, &mut w_fwd);
    let w_inv: Vec<c64> = w_fwd.iter().map(|z| z.conj()).collect();
    (w_fwd, w_inv)
}

// ---------------------------------------------------------------------------
// Scalar helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn c64_add(a: c64, b: c64) -> c64 {
    c64::new(a.re + b.re, a.im + b.im)
}
#[inline(always)]
fn c64_sub(a: c64, b: c64) -> c64 {
    c64::new(a.re - b.re, a.im - b.im)
}
#[inline(always)]
fn c64_mul(a: c64, b: c64) -> c64 {
    c64::new(
        f64::mul_add(a.re, b.re, -a.im * b.im),
        f64::mul_add(a.re, b.im, a.im * b.re),
    )
}
#[inline(always)]
fn c64_mul_j(fwd: bool, z: c64) -> c64 {
    if fwd {
        c64::new(-z.im, z.re)
    } else {
        c64::new(z.im, -z.re)
    }
}
#[inline(always)]
fn split_2<T>(s: &[T]) -> (&[T], &[T]) {
    s.split_at(s.len() / 2)
}
#[inline(always)]
fn split_mut_2<T>(s: &mut [T]) -> (&mut [T], &mut [T]) {
    s.split_at_mut(s.len() / 2)
}
#[inline(always)]
fn split_4<T>(s: &[T]) -> (&[T], &[T], &[T], &[T]) {
    let n4 = s.len() / 4;
    let (a, r) = s.split_at(n4);
    let (b, r) = r.split_at(n4);
    let (c, d) = r.split_at(n4);
    (a, b, c, d)
}
#[inline(always)]
fn split_mut_4<T>(s: &mut [T]) -> (&mut [T], &mut [T], &mut [T], &mut [T]) {
    let n4 = s.len() / 4;
    let (a, r) = s.split_at_mut(n4);
    let (b, r) = r.split_at_mut(n4);
    let (c, d) = r.split_at_mut(n4);
    (a, b, c, d)
}

/// Reinterpret `&[c64]` as `&[[c64; K]]`.
#[inline(always)]
unsafe fn as_arrays<const K: usize>(slice: &[c64]) -> &[[c64; K]] {
    unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const [c64; K], slice.len() / K) }
}

// ---------------------------------------------------------------------------
// Radix-4 stockham core — scalar
// ---------------------------------------------------------------------------

fn fwd_butterfly_r4(
    z0: c64,
    z1: c64,
    z2: c64,
    z3: c64,
    w1: c64,
    w2: c64,
    w3: c64,
) -> (c64, c64, c64, c64) {
    let apc = c64_add(z0, z2);
    let amc = c64_sub(z0, z2);
    let bpd = c64_add(z1, z3);
    let jbmd = c64_mul_j(true, c64_sub(z1, z3));
    // mul_j(true) = +i*z. jbmd = +i*(b-d).
    // r1 = (a - i*b - c + i*d)*w1 = (amc - jbmd)*w1 = X[1]
    // r3 = (a + i*b - c - i*d)*w3 = (amc + jbmd)*w3 = X[3]
    (
        c64_add(apc, bpd),
        c64_mul(w1, c64_sub(amc, jbmd)),
        c64_mul(w2, c64_sub(apc, bpd)),
        c64_mul(w3, c64_add(amc, jbmd)),
    )
}
fn inv_butterfly_r4(
    z0: c64,
    z1: c64,
    z2: c64,
    z3: c64,
    w1: c64,
    w2: c64,
    w3: c64,
) -> (c64, c64, c64, c64) {
    let z1 = c64_mul(w1, z1);
    let z2 = c64_mul(w2, z2);
    let z3 = c64_mul(w3, z3);
    let apc = c64_add(z0, z2);
    let amc = c64_sub(z0, z2);
    let bpd = c64_add(z1, z3);
    let jbmd = c64_mul_j(false, c64_sub(z1, z3));
    // mul_j(false) = -i*z. jbmd = -i*(b-d).
    (
        c64_add(apc, bpd),
        c64_sub(amc, jbmd),
        c64_sub(apc, bpd),
        c64_add(amc, jbmd),
    )
}
fn last_butterfly_r4(fwd: bool, z0: c64, z1: c64, z2: c64, z3: c64) -> (c64, c64, c64, c64) {
    let apc = c64_add(z0, z2);
    let amc = c64_sub(z0, z2);
    let bpd = c64_add(z1, z3);
    let jbmd = c64_mul_j(fwd, c64_sub(z1, z3));
    (
        c64_add(apc, bpd),
        c64_sub(amc, jbmd),
        c64_sub(apc, bpd),
        c64_add(amc, jbmd),
    )
}

fn stockham_core_r4_scalar(data: &[c64], scratch: &mut [c64], w: &[c64], s: usize, fwd: bool) {
    let n = data.len();
    debug_assert_eq!(scratch.len(), n);
    let w4 = unsafe { as_arrays::<4>(w) };
    let (x0, x1, x2, x3) = split_4(data);
    let (y0, y1, y2, y3) = split_mut_4(scratch);
    for b in 0..n / (4 * s) {
        let base = b * s;
        let [_, w1, w2, w3] = w4[base];
        for k in 0..s {
            let idx = base + k;
            let (r0, r1, r2, r3) = if fwd {
                fwd_butterfly_r4(x0[idx], x1[idx], x2[idx], x3[idx], w1, w2, w3)
            } else {
                inv_butterfly_r4(x0[idx], x1[idx], x2[idx], x3[idx], w1, w2, w3)
            };
            y0[idx] = r0;
            y1[idx] = r1;
            y2[idx] = r2;
            y3[idx] = r3;
        }
    }
}

fn stockham_dif4_end_scalar(data: &[c64], scratch: &mut [c64], fwd: bool) {
    let n = data.len();
    for i in 0..n / 4 {
        let (r0, r1, r2, r3) = last_butterfly_r4(
            fwd,
            data[i],
            data[i + n / 4],
            data[i + n / 2],
            data[i + 3 * n / 4],
        );
        scratch[i] = r0;
        scratch[i + n / 4] = r1;
        scratch[i + n / 2] = r2;
        scratch[i + 3 * n / 4] = r3;
    }
}

// ---------------------------------------------------------------------------
// Radix-2 stockham core — scalar
// ---------------------------------------------------------------------------

fn fwd_butterfly_r2(z0: c64, z1: c64, w1: c64) -> (c64, c64) {
    (c64_add(z0, z1), c64_mul(w1, c64_sub(z0, z1)))
}
fn inv_butterfly_r2(z0: c64, z1: c64, w1: c64) -> (c64, c64) {
    let z1 = c64_mul(w1, z1);
    (c64_add(z0, z1), c64_sub(z0, z1))
}
fn last_butterfly_r2(z0: c64, z1: c64) -> (c64, c64) {
    (c64_add(z0, z1), c64_sub(z0, z1))
}

fn stockham_core_r2_scalar(data: &[c64], scratch: &mut [c64], w: &[c64], s: usize, fwd: bool) {
    let n = data.len();
    debug_assert_eq!(scratch.len(), n);
    let w2 = unsafe { as_arrays::<2>(w) };
    let (x0, x1) = split_2(data);
    for b in 0..n / (2 * s) {
        let block_start = b * 2 * s;
        let base = b * s;
        let [_, w1] = w2[base];
        for k in 0..s {
            let idx = base + k;
            let (r0, r1) = if fwd {
                fwd_butterfly_r2(x0[idx], x1[idx], w1)
            } else {
                inv_butterfly_r2(x0[idx], x1[idx], w1)
            };
            // Stockham blocked layout: sums in first half, diffs in second half
            scratch[block_start + k] = r0;
            scratch[block_start + s + k] = r1;
        }
    }
}

fn stockham_dif2_end_scalar(data: &[c64], scratch: &mut [c64]) {
    let n = data.len();
    for i in 0..n / 2 {
        let (r0, r1) = last_butterfly_r2(data[i], data[i + n / 2]);
        scratch[i] = r0;
        scratch[i + n / 2] = r1;
    }
}

// ---------------------------------------------------------------------------
// AVX2 path (x86_64 only)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod avx2 {
    use super::*;
    use std::arch::x86_64::*;

    #[derive(Copy, Clone, Debug)]
    #[repr(C)]
    pub struct c64x2(pub(crate) __m256d);

    #[inline(always)]
    unsafe fn as_c64x2(slice: &[c64]) -> &[c64x2] {
        unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const c64x2, slice.len() / 2) }
    }
    #[inline(always)]
    unsafe fn as_c64x2_mut(slice: &mut [c64]) -> &mut [c64x2] {
        unsafe { std::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut c64x2, slice.len() / 2) }
    }

    // ---- SIMD primitives ----

    #[inline(always)]
    unsafe fn splat(value: c64) -> c64x2 {
        let lo = unsafe { _mm_setr_pd(value.re, value.im) };
        c64x2(unsafe { _mm256_insertf128_pd(_mm256_castpd128_pd256(lo), lo, 1) })
    }
    #[inline(always)]
    unsafe fn add(a: c64x2, b: c64x2) -> c64x2 {
        c64x2(unsafe { _mm256_add_pd(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn sub(a: c64x2, b: c64x2) -> c64x2 {
        c64x2(unsafe { _mm256_sub_pd(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn mul(a: c64x2, b: c64x2) -> c64x2 {
        let ab = a.0;
        let xy = b.0;
        let yx = unsafe { _mm256_permute_pd::<0b0101>(xy) };
        let aa = unsafe { _mm256_unpacklo_pd(ab, ab) };
        let bb = unsafe { _mm256_unpackhi_pd(ab, ab) };
        c64x2(unsafe { _mm256_fmsub_pd(aa, xy, _mm256_mul_pd(bb, yx)) })
    }
    #[inline(always)]
    unsafe fn xor(a: c64x2, b: c64x2) -> c64x2 {
        c64x2(unsafe { _mm256_xor_pd(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn swap_re_im(xy: c64x2) -> c64x2 {
        c64x2(unsafe { _mm256_permute_pd::<0b0101>(xy.0) })
    }
    #[inline(always)]
    unsafe fn conj(xy: c64x2) -> c64x2 {
        let mask = unsafe { _mm256_setr_pd(0.0, -0.0, 0.0, -0.0) };
        unsafe { xor(xy, c64x2(mask)) }
    }
    #[inline(always)]
    unsafe fn mul_j(fwd: bool, xy: c64x2) -> c64x2 {
        if fwd {
            unsafe { swap_re_im(conj(xy)) }
        } else {
            unsafe { conj(swap_re_im(xy)) }
        }
    }
    #[inline(always)]
    unsafe fn catlo(a: c64x2, b: c64x2) -> c64x2 {
        c64x2(unsafe { _mm256_permute2f128_pd::<0b0010_0000>(a.0, b.0) })
    }
    #[inline(always)]
    unsafe fn cathi(a: c64x2, b: c64x2) -> c64x2 {
        c64x2(unsafe { _mm256_permute2f128_pd::<0b0011_0001>(a.0, b.0) })
    }

    // ---- Radix-4 AVX2 ----

    #[target_feature(enable = "avx2,fma")]
    unsafe fn stockham_core_r4_s1(data: &[c64], scratch: &mut [c64], w_init: &[c64], fwd: bool) {
        let n = data.len();
        let n2 = n / 2;
        let n4 = n2 / 4;
        let dv = unsafe { as_c64x2(data) };
        let sv = unsafe { as_c64x2_mut(scratch) };

        let x0 = &dv[0..n4];
        let x1 = &dv[n4..2 * n4];
        let x2 = &dv[2 * n4..3 * n4];
        let x3 = &dv[3 * n4..n2];

        // Use split_at_mut to avoid multiple mutable borrows
        let (y0, rest) = sv.split_at_mut(n4);
        let (y1, rest) = rest.split_at_mut(n4);
        let (y2, y3) = rest.split_at_mut(n4);

        let w1_arr = &w_init[n / 4..2 * n / 4];
        let w2_arr = &w_init[2 * n / 4..3 * n / 4];
        let w3_arr = &w_init[3 * n / 4..n];

        for i in 0..n4 {
            let a = x0[i];
            let b = x1[i];
            let c = x2[i];
            let d = x3[i];
            let w1 = unsafe { splat(w1_arr[i]) };
            let w2 = unsafe { splat(w2_arr[i]) };
            let w3 = unsafe { splat(w3_arr[i]) };

            let apc = unsafe { add(a, c) };
            let amc = unsafe { sub(a, c) };
            let bpd = unsafe { add(b, d) };
            let jbmd = unsafe { mul_j(fwd, sub(b, d)) };

            let aa = unsafe { add(apc, bpd) };
            let bb = unsafe { mul(w1, sub(amc, jbmd)) };
            let cc = unsafe { mul(w2, sub(apc, bpd)) };
            let dd = unsafe { mul(w3, add(amc, jbmd)) };

            let ab_lo = unsafe { catlo(aa, bb) };
            let cd_lo = unsafe { catlo(cc, dd) };
            let ab_hi = unsafe { cathi(aa, bb) };
            let cd_hi = unsafe { cathi(cc, dd) };

            y0[i] = unsafe { catlo(ab_lo, cd_lo) };
            y1[i] = unsafe { cathi(ab_lo, cd_lo) };
            y2[i] = unsafe { catlo(ab_hi, cd_hi) };
            y3[i] = unsafe { cathi(ab_hi, cd_hi) };
        }
    }

    #[target_feature(enable = "avx2,fma")]
    unsafe fn stockham_core_r4_generic(
        data: &[c64],
        scratch: &mut [c64],
        w: &[c64],
        s: usize,
        fwd: bool,
    ) {
        let n = data.len();
        debug_assert!(s % 2 == 0);
        let simd_s = s / 2;
        let n2 = n / 2;
        let n4 = n2 / 4;
        let dv = unsafe { as_c64x2(data) };
        let sv = unsafe { as_c64x2_mut(scratch) };
        let w4 = unsafe { as_arrays::<4>(w) };

        let x0 = &dv[0..n4];
        let x1 = &dv[n4..2 * n4];
        let x2 = &dv[2 * n4..3 * n4];
        let x3 = &dv[3 * n4..n2];

        let (y0, rest) = sv.split_at_mut(n4);
        let (y1, rest) = rest.split_at_mut(n4);
        let (y2, y3) = rest.split_at_mut(n4);

        for b in 0..n / (4 * s) {
            let base = b * simd_s;
            let [_, w1, w2, w3] = w4[b * s];
            let w1 = unsafe { splat(w1) };
            let w2 = unsafe { splat(w2) };
            let w3 = unsafe { splat(w3) };
            for k in 0..simd_s {
                let idx = base + k;
                let a = x0[idx];
                let b = x1[idx];
                let c = x2[idx];
                let d = x3[idx];
                let apc = unsafe { add(a, c) };
                let amc = unsafe { sub(a, c) };
                let bpd = unsafe { add(b, d) };
                let jbmd = unsafe { mul_j(fwd, sub(b, d)) };
                if fwd {
                    y0[idx] = unsafe { add(apc, bpd) };
                    y1[idx] = unsafe { mul(w1, sub(amc, jbmd)) };
                    y2[idx] = unsafe { mul(w2, sub(apc, bpd)) };
                    y3[idx] = unsafe { mul(w3, add(amc, jbmd)) };
                } else {
                    y0[idx] = unsafe { add(apc, bpd) };
                    y1[idx] = unsafe { sub(amc, jbmd) };
                    y2[idx] = unsafe { sub(apc, bpd) };
                    y3[idx] = unsafe { add(amc, jbmd) };
                }
            }
        }
    }

    #[target_feature(enable = "avx2,fma")]
    pub unsafe fn stockham_core_r4(
        data: &[c64],
        scratch: &mut [c64],
        w_full: &[c64],
        s: usize,
        fwd: bool,
    ) {
        let n = data.len();
        if s == 1 {
            unsafe { stockham_core_r4_s1(data, scratch, &w_full[..n], fwd) }
        } else {
            unsafe { stockham_core_r4_generic(data, scratch, &w_full[n..], s, fwd) }
        }
    }

    #[target_feature(enable = "avx2,fma")]
    pub unsafe fn stockham_dif4_end(data: &[c64], scratch: &mut [c64], fwd: bool) {
        let n = data.len();
        let n2 = n / 2;
        let n4 = n2 / 4;
        let dv = unsafe { as_c64x2(data) };
        let sv = unsafe { as_c64x2_mut(scratch) };

        let x0 = &dv[0..n4];
        let x1 = &dv[n4..2 * n4];
        let x2 = &dv[2 * n4..3 * n4];
        let x3 = &dv[3 * n4..n2];

        let (y0, rest) = sv.split_at_mut(n4);
        let (y1, rest) = rest.split_at_mut(n4);
        let (y2, y3) = rest.split_at_mut(n4);

        for i in 0..n4 {
            let a = x0[i];
            let b = x1[i];
            let c = x2[i];
            let d = x3[i];
            let apc = unsafe { add(a, c) };
            let amc = unsafe { sub(a, c) };
            let bpd = unsafe { add(b, d) };
            let jbmd = unsafe { mul_j(fwd, sub(b, d)) };
            y0[i] = unsafe { add(apc, bpd) };
            y1[i] = unsafe { sub(amc, jbmd) };
            y2[i] = unsafe { sub(apc, bpd) };
            y3[i] = unsafe { add(amc, jbmd) };
        }
    }

    // ---- Radix-2 AVX2 ----

    #[target_feature(enable = "avx2,fma")]
    unsafe fn stockham_core_r2_s1(data: &[c64], scratch: &mut [c64], w_init: &[c64], _fwd: bool) {
        let n = data.len();
        let n2 = n / 2;
        let dv = unsafe { as_c64x2(data) };
        let sv = unsafe { as_c64x2_mut(scratch) };
        let x0 = &dv[0..n2 / 2];
        let x1 = &dv[n2 / 2..n2];
        let w1_arr = &w_init[n / 2..];

        for i in 0..n2 / 2 {
            let a = x0[i];
            let b = x1[i];
            let w1 = unsafe { splat(w1_arr[i]) };
            let aa = unsafe { add(a, b) };
            let bb = unsafe { mul(w1, sub(a, b)) };
            sv[i] = unsafe { catlo(aa, bb) };
            sv[i + n2 / 2] = unsafe { cathi(aa, bb) };
        }
    }

    #[target_feature(enable = "avx2,fma")]
    unsafe fn stockham_core_r2_generic(
        data: &[c64],
        scratch: &mut [c64],
        w: &[c64],
        s: usize,
        fwd: bool,
    ) {
        let n = data.len();
        debug_assert!(s % 2 == 0);
        let simd_s = s / 2;
        let n2 = n / 2;
        let dv = unsafe { as_c64x2(data) };
        let sv = unsafe { as_c64x2_mut(scratch) };
        let w2 = unsafe { as_arrays::<2>(w) };

        let x0 = &dv[0..n2 / 2];
        let x1 = &dv[n2 / 2..n2];

        for b in 0..n / (2 * s) {
            let block_start = b * s; // in c64x2 units: b * simd_s
            let base = b * simd_s;
            let [_, w1] = w2[b * s];
            let w1 = unsafe { splat(w1) };
            for k in 0..simd_s {
                let idx = base + k;
                let a = x0[idx];
                let b = x1[idx];
                let sum = unsafe { add(a, b) };
                let diff = if fwd {
                    unsafe { mul(w1, sub(a, b)) }
                } else {
                    let b = unsafe { mul(w1, b) };
                    unsafe { sub(a, b) }
                };
                // Stockham blocked: sums in first half of block, diffs in second half
                sv[block_start + k] = sum;
                sv[block_start + simd_s + k] = diff;
            }
        }
    }

    #[target_feature(enable = "avx2,fma")]
    pub unsafe fn stockham_core_r2(
        data: &[c64],
        scratch: &mut [c64],
        w_full: &[c64],
        s: usize,
        fwd: bool,
    ) {
        let n = data.len();
        if s == 1 && n >= 4 {
            unsafe { stockham_core_r2_s1(data, scratch, &w_full[..n], fwd) }
        } else {
            unsafe { stockham_core_r2_generic(data, scratch, &w_full[n..], s, fwd) }
        }
    }

    #[target_feature(enable = "avx2,fma")]
    pub unsafe fn stockham_dif2_end(data: &[c64], scratch: &mut [c64]) {
        let n = data.len();
        let n2 = n / 2;
        let dv = unsafe { as_c64x2(data) };
        let sv = unsafe { as_c64x2_mut(scratch) };
        let x0 = &dv[0..n2 / 2];
        let x1 = &dv[n2 / 2..n2];
        let (y0, y1) = sv.split_at_mut(n2 / 2);
        for i in 0..n2 / 2 {
            y0[i] = unsafe { add(x0[i], x1[i]) };
            y1[i] = unsafe { sub(x0[i], x1[i]) };
        }
    }
}

// ---------------------------------------------------------------------------
// StockhamFft — public API
// ---------------------------------------------------------------------------

/// Stockham DIF radix-2 FFT engine for complex-to-complex transforms.
///
/// Supports power-of-two sizes with scalar fallback and optional AVX2
/// acceleration. FFT convention: forward uses `exp(-i·2π·k·m/n)`, inverse
/// uses `exp(+i·2π·k·m/n)`.
pub struct StockhamFft {
    n: usize,
    twiddles_fwd: Vec<c64>,
    twiddles_inv: Vec<c64>,
    scratch: UnsafeCell<Vec<c64>>,
    use_avx2: bool,
}

unsafe impl Sync for StockhamFft {}

impl StockhamFft {
    /// Create a new Stockham FFT engine for size `n` (must be a power of two, ≥ 2).
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two(), "n must be a power of 2");
        assert!(n >= 2, "n must be at least 2");
        // Use r=2 for twiddle init (works for all power-of-2 sizes).
        // Mixed-radix r=4 init would need separate layouts; keep it simple.
        let (twiddles_fwd, twiddles_inv) = init_wt_pair(2, n);
        // AVX2 temporarily disabled: needs proper 32-byte aligned buffer
        // allocation for `c64x2` (_mm256_load/store require alignment or
        // unaligned variants).
        let use_avx2 = false;
        let _ = (cfg!(target_arch = "x86_64")
            && is_x86_feature_detected!("avx2")
            && is_x86_feature_detected!("fma")
            && n >= 4);
        Self {
            n,
            twiddles_fwd,
            twiddles_inv,
            scratch: UnsafeCell::new(vec![c64::default(); n]),
            use_avx2,
        }
    }

    /// Number of complex elements in the FFT.
    #[inline]
    #[allow(dead_code)]
    pub fn n(&self) -> usize {
        self.n
    }

    /// Forward FFT (in-place). Uses `exp(-i·2π·k·m/n)` convention.
    pub fn forward(&self, data: &mut [c64]) {
        debug_assert_eq!(data.len(), self.n);
        let scratch = unsafe { &mut *self.scratch.get() };
        stockham_dif(data, scratch, &self.twiddles_fwd, self.use_avx2, true);
    }

    /// Inverse FFT (in-place). Uses `exp(+i·2π·k·m/n)` convention.
    pub fn inverse(&self, data: &mut [c64]) {
        debug_assert_eq!(data.len(), self.n);
        let scratch = unsafe { &mut *self.scratch.get() };
        stockham_dif(data, scratch, &self.twiddles_inv, self.use_avx2, true);
    }
}

// ---------------------------------------------------------------------------
// Core iterative Stockham DIF
// ---------------------------------------------------------------------------

fn stockham_dif(
    data: &mut [c64],
    scratch: &mut [c64],
    twiddles: &[c64],
    use_avx2: bool,
    fwd: bool,
) {
    let n = data.len();
    if n < 2 {
        return;
    }

    let mut s: usize = 1;
    let mut read_from_data = true;

    // radix-2 stages while s*2 < n (with twiddles)
    while s * 2 < n {
        if use_avx2 {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                if read_from_data {
                    avx2::stockham_core_r2(data, scratch, twiddles, s, fwd);
                } else {
                    avx2::stockham_core_r2(scratch, data, twiddles, s, fwd);
                }
            }
        } else {
            if read_from_data {
                stockham_core_r2_scalar(data, scratch, &twiddles[n..], s, fwd);
            } else {
                stockham_core_r2_scalar(scratch, data, &twiddles[n..], s, fwd);
            }
        }
        s *= 2;
        read_from_data = !read_from_data;
    }

    // final radix-2 butterfly (no twiddles)
    debug_assert!(s * 2 == n, "expected s*2=n, got s={s}, n={n}");
    if use_avx2 {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if read_from_data {
                avx2::stockham_dif2_end(data, scratch);
            } else {
                avx2::stockham_dif2_end(scratch, data);
            }
        }
    } else {
        if read_from_data {
            stockham_dif2_end_scalar(data, scratch);
        } else {
            stockham_dif2_end_scalar(scratch, data);
        }
    }
    read_from_data = !read_from_data;

    if !read_from_data {
        data.copy_from_slice(scratch);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sincospi64_basic() {
        let (s, c) = sincospi64(0.0);
        assert!((s - 0.0).abs() < 1e-15);
        assert!((c - 1.0).abs() < 1e-15);
        let (s, c) = sincospi64(0.5);
        assert!((s - 1.0).abs() < 1e-15);
        assert!((c - 0.0).abs() < 1e-15);
        for &x in &[-10.0, -3.5, -1.0, -0.25, 0.25, 1.0, 3.5, 10.0] {
            let (s, c) = sincospi64(x);
            assert!((s - (PI * x).sin()).abs() < 1e-12, "sin mismatch at x={x}");
            assert!((c - (PI * x).cos()).abs() < 1e-12, "cos mismatch at x={x}");
        }
    }

    #[test]
    fn test_stockham_roundtrip() {
        for log_n in 1..=10 {
            let n = 1 << log_n;
            let fft = StockhamFft::new(n);
            let mut data: Vec<c64> = (0..n)
                .map(|_| {
                    c64::new(
                        rand::random::<f64>() * 2.0 - 1.0,
                        rand::random::<f64>() * 2.0 - 1.0,
                    )
                })
                .collect();
            let orig = data.clone();
            fft.forward(&mut data);
            fft.inverse(&mut data);
            for z in &mut data {
                *z /= n as f64;
            }
            for (i, (a, b)) in orig.iter().zip(&data).enumerate() {
                let scale = 1.0f64.max(a.norm()).max(b.norm());
                assert!(
                    (a - b).norm() < 1e-12 * scale,
                    "roundtrip mismatch at {i} for n={n}"
                );
            }
        }
    }

    #[test]
    fn test_stockham_vs_rustfft() {
        use rustfft::FftPlanner;
        for log_n in 1..=10 {
            let n = 1 << log_n;
            let fft = StockhamFft::new(n);
            let mut data: Vec<c64> = (0..n)
                .map(|_| {
                    c64::new(
                        rand::random::<f64>() * 2.0 - 1.0,
                        rand::random::<f64>() * 2.0 - 1.0,
                    )
                })
                .collect();
            let orig = data.clone();
            fft.forward(&mut data);
            let mut planner = FftPlanner::new();
            let rf = planner.plan_fft_forward(n);
            let mut expected = orig.clone();
            rf.process(&mut expected);
            for (i, (a, b)) in data.iter().zip(&expected).enumerate() {
                let scale = 1.0f64.max(a.norm()).max(b.norm());
                assert!(
                    (a - b).norm() < 1e-12 * scale,
                    "forward mismatch at {i} for n={n}"
                );
            }
            let mut inv = expected.clone();
            fft.inverse(&mut inv);
            for z in &mut inv {
                *z /= n as f64;
            }
            for (i, (a, b)) in orig.iter().zip(&inv).enumerate() {
                let scale = 1.0f64.max(a.norm()).max(b.norm());
                assert!(
                    (a - b).norm() < 1e-12 * scale,
                    "inverse mismatch at {i} for n={n}"
                );
            }
        }
    }
}
