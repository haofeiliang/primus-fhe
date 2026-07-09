//! Packed negacyclic FFT table — tfhe-rs style (first-half/second-half + 1 FFT).
//!
//! See [`crate::experimental`] for the mathematical background.  In short:
//! - Standard FFT of size N computes `mod X^N−1` (cyclic) convolution.
//! - For `mod X^N+1` (negacyclic), we evaluate at odd powers `ζ^(2k+1)` of a
//!   primitive 2N-th root of unity `ζ = exp(i·π/N)`.
//! - The old packed approach split the polynomial into even/odd parts, requiring
//!   **2 FFTs** of size N/2 plus a combine step.
//! - This module follows tfhe-rs: first N/2 coefficients → "real", second N/2
//!   → "imaginary", twist by `exp(i·π·m/N)`, then a **single FFT** of size N/2.
//! - The inverse is: IFFT → untwist → interleave real/imag back to two halves.
//!
//! This cuts FFT work in half compared to the even/odd approach, while
//! preserving the negacyclic convolution property `mod X^N+1`.

use std::cell::UnsafeCell;
use std::f64::consts::PI;
use std::sync::Arc;

use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};

use crate::error::FftError;
use crate::table::FftTable;
use crate::torus::TorusFftValue;

// ---------------------------------------------------------------------------
// Twisties — 2N-th roots of unity
// ---------------------------------------------------------------------------

struct Twisties {
    poly_length: usize,    // N
    fourier_length: usize, // h = N/2

    /// `cos(π·m/N)` for forward twist.
    twist_re: Vec<f64>,
    /// `sin(π·m/N)` for forward twist.
    twist_im: Vec<f64>,

    /// `cos(π·m/N) / h` for inverse untwist (pre-scaled by 1/h).
    inv_twist_re_scaled: Vec<f64>,
    /// `-sin(π·m/N) / h` for inverse untwist.
    inv_twist_im_scaled: Vec<f64>,
}

impl Twisties {
    fn new(log_n: u32) -> Self {
        let n = 1usize << log_n;
        let h = n / 2;
        let n_f64 = n as f64;
        let h_f64 = h as f64;
        let scale = 1.0 / h_f64;

        let mut twist_re = Vec::with_capacity(h);
        let mut twist_im = Vec::with_capacity(h);
        let mut inv_twist_re_scaled = Vec::with_capacity(h);
        let mut inv_twist_im_scaled = Vec::with_capacity(h);
        for m in 0..h {
            let theta = PI * m as f64 / n_f64;
            let tr = theta.cos();
            let ti = theta.sin();
            twist_re.push(tr);
            twist_im.push(ti);
            inv_twist_re_scaled.push(tr * scale);
            inv_twist_im_scaled.push(-ti * scale);
        }

        Self {
            poly_length: n,
            fourier_length: h,
            twist_re,
            twist_im,
            inv_twist_re_scaled,
            inv_twist_im_scaled,
        }
    }
}

// ---------------------------------------------------------------------------
// PackedFftTable
// ---------------------------------------------------------------------------

/// Scratch buffers for the negacyclic transform.
struct Scratch {
    /// Complex scratch (length h).
    scratch: Vec<Complex64>,
    /// Scratch required by rustfft plans.
    fft_scratch: Vec<Complex64>,
}

impl Scratch {
    fn new(h: usize, fft_scratch_len: usize) -> Self {
        Self {
            scratch: vec![Complex64::new(0.0, 0.0); h],
            fft_scratch: vec![Complex64::new(0.0, 0.0); fft_scratch_len],
        }
    }
}

/// Packed negacyclic FFT table — tfhe-rs style (first-half/second-half + 1 FFT).
pub struct PackedFftTable {
    log_n: u32,
    tables: Twisties,
    /// h-point FFT with `exp(+i…)` convention (rustfft inverse planner).
    fft_half: Arc<dyn Fft<f64>>,
    /// h-point FFT with `exp(−i…)` convention (rustfft forward planner).
    ifft_half: Arc<dyn Fft<f64>>,
    scratch: UnsafeCell<Scratch>,
}

// SAFETY: scratch buffers are only accessed from &self methods that are never
// called concurrently on the same instance.
unsafe impl Sync for PackedFftTable {}

impl PackedFftTable {
    /// Returns `log2(N)`.
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }
}

impl FftTable for PackedFftTable {
    fn new(log_n: u32) -> Result<Self, FftError> {
        if log_n < 2 {
            return Err(FftError::InvalidLogN {
                log_n,
                max: usize::BITS - 1,
            });
        }

        let n = 1usize << log_n;
        let h = n / 2;
        let tables = Twisties::new(log_n);

        let mut planner = FftPlanner::new();
        // Swapped: rustfft inverse gives the positive-sign convention needed
        // for forward packed decomposition; forward gives the inverse pass.
        let fft_half = planner.plan_fft_inverse(h);
        let ifft_half = planner.plan_fft_forward(h);
        let fft_scratch_len = fft_half
            .get_inplace_scratch_len()
            .max(ifft_half.get_inplace_scratch_len());

        let scratch = UnsafeCell::new(Scratch::new(h, fft_scratch_len));

        Ok(Self {
            log_n,
            tables,
            fft_half,
            ifft_half,
            scratch,
        })
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.tables.poly_length
    }

    #[inline]
    fn fourier_length(&self) -> usize {
        self.tables.fourier_length
    }

    fn forward_torus_slice<T: TorusFftValue>(&self, input: &[T], output: &mut [f64]) {
        let n = self.tables.poly_length;
        let h = self.tables.fourier_length;
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(output.len(), 2 * h);

        let scratch = unsafe { &mut *self.scratch.get() };

        // Step 1: first-half/second-half split, center, twist → Complex64.
        let (first, second) = input.split_at(h);
        for m in 0..h {
            let re = first[m].into_f64_centered();
            let im = second[m].into_f64_centered();
            let tr = self.tables.twist_re[m];
            let ti = self.tables.twist_im[m];
            scratch.scratch[m] = Complex64::new(
                f64::mul_add(re, tr, -im * ti),
                f64::mul_add(re, ti, im * tr),
            );
        }

        // Step 2: single h-point FFT (exp(+i) convention = rustfft inverse).
        self.fft_half
            .process_with_scratch(&mut scratch.scratch, &mut scratch.fft_scratch);

        // Step 3: output in split [re|im].
        let (out_re, out_im) = output.split_at_mut(h);
        for m in 0..h {
            out_re[m] = scratch.scratch[m].re;
            out_im[m] = scratch.scratch[m].im;
        }
    }

    fn forward_centered_f64_slice(&self, input: &[f64], output: &mut [f64]) {
        let n = self.tables.poly_length;
        let h = self.tables.fourier_length;
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(output.len(), 2 * h);

        let scratch = unsafe { &mut *self.scratch.get() };

        // Step 1: first-half/second-half split, twist (no centering).
        let (first, second) = input.split_at(h);
        for m in 0..h {
            let re = first[m];
            let im = second[m];
            let tr = self.tables.twist_re[m];
            let ti = self.tables.twist_im[m];
            scratch.scratch[m] = Complex64::new(
                f64::mul_add(re, tr, -im * ti),
                f64::mul_add(re, ti, im * tr),
            );
        }

        // Step 2: single h-point FFT.
        self.fft_half
            .process_with_scratch(&mut scratch.scratch, &mut scratch.fft_scratch);

        // Step 3: output in split [re|im].
        let (out_re, out_im) = output.split_at_mut(h);
        for m in 0..h {
            out_re[m] = scratch.scratch[m].re;
            out_im[m] = scratch.scratch[m].im;
        }
    }

    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[f64], output: &mut [T]) {
        let n = self.tables.poly_length;
        let h = self.tables.fourier_length;
        debug_assert_eq!(input.len(), 2 * h);
        debug_assert_eq!(output.len(), n);

        let scratch = unsafe { &mut *self.scratch.get() };
        let (p_re, p_im) = input.split_at(h);

        // Step 1: load from split [re|im] → Complex64.
        for m in 0..h {
            scratch.scratch[m] = Complex64::new(p_re[m], p_im[m]);
        }

        // Step 2: single h-point inverse FFT (exp(-i) convention = rustfft forward).
        self.ifft_half
            .process_with_scratch(&mut scratch.scratch, &mut scratch.fft_scratch);

        // Step 3: untwist, round, and interleave.
        for m in 0..h {
            let itr = self.tables.inv_twist_re_scaled[m]; // cos(π·m/N) / h
            let iti = self.tables.inv_twist_im_scaled[m]; // -sin(π·m/N) / h
            let v = scratch.scratch[m];
            let re_out = f64::mul_add(v.re, itr, -v.im * iti);
            let im_out = f64::mul_add(v.re, iti, v.im * itr);
            output[m] = T::from_f64_wrapping_rounded(re_out);
            output[m + h] = T::from_f64_wrapping_rounded(im_out);
        }
    }
}
