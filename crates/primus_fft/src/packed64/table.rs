use std::cell::UnsafeCell;
use std::f64::consts::PI;
use std::sync::Arc;

use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};

use crate::error::FftError;
use crate::table::FftTable;
use crate::torus::TorusFftValue;

/// Packed negacyclic FFT table with `fourier_length = N / 2`.
///
/// This backend keeps the fast rustfft half-size FFT core. Forward
/// pre/post-processing uses split `f64` twiddle tables to avoid temporary
/// `Complex64` arithmetic in the hot decomposition path. The inverse keeps
/// precomputed complex roots/twists, which currently benchmarks better for the
/// reconstruction and rounding path.
///
/// All Fourier buffers use split `[re | im]` f64 layout.
///
/// # Scratch buffers
///
/// Pre-allocated scratch is guarded by [`UnsafeCell`] -- same safety contract as
/// [`crate::complex64::FftTableImpl`]: the caller must not call the transform
/// methods concurrently on the same instance.
pub struct PackedFftTable {
    log_n: u32,
    poly_length: usize,
    fourier_length: usize,
    /// N/2-point FFT with exp(+i...) convention.
    fft_half: Arc<dyn Fft<f64>>,
    /// N/2-point FFT with exp(-i...) convention.
    ifft_half: Arc<dyn Fft<f64>>,
    /// `omega_k = exp(i*pi*(2k+1)/N)` for the final combine.
    roots_re: Vec<f64>,
    roots_im: Vec<f64>,
    roots_half: Vec<Complex64>,
    /// `psi_m = exp(i*2*pi*m/N)` for even/odd split twisting.
    twist_re: Vec<f64>,
    twist_im: Vec<f64>,
    inv_twist_scaled: Vec<Complex64>,
    /// Scratch for even part, length N/2.
    scratch_a: UnsafeCell<Vec<Complex64>>,
    /// Scratch for odd part, length N/2.
    scratch_b: UnsafeCell<Vec<Complex64>>,
    /// Scratch required by rustfft plans.
    fft_scratch: UnsafeCell<Vec<Complex64>>,
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
        let half_n = n / 2;

        let mut planner = FftPlanner::new();
        // Swapped: rustfft inverse gives the positive-sign convention needed
        // for forward packed decomposition; forward gives the inverse pass.
        let fft_half = planner.plan_fft_inverse(half_n);
        let ifft_half = planner.plan_fft_forward(half_n);
        let fft_scratch_len = fft_half
            .get_inplace_scratch_len()
            .max(ifft_half.get_inplace_scratch_len());

        let n_f64 = n as f64;
        let scale = 1.0 / (half_n as f64);

        let mut roots_re = Vec::with_capacity(half_n);
        let mut roots_im = Vec::with_capacity(half_n);
        let mut roots_half = Vec::with_capacity(half_n);
        for k in 0..half_n {
            let theta = PI * (2 * k + 1) as f64 / n_f64;
            let root = Complex64::new(theta.cos(), theta.sin());
            roots_re.push(root.re);
            roots_im.push(root.im);
            roots_half.push(root);
        }

        let mut twist_re = Vec::with_capacity(half_n);
        let mut twist_im = Vec::with_capacity(half_n);
        let mut inv_twist_scaled = Vec::with_capacity(half_n);
        for m in 0..half_n {
            let theta = 2.0 * PI * m as f64 / n_f64;
            let tr = theta.cos();
            let ti = theta.sin();
            twist_re.push(tr);
            twist_im.push(ti);
            inv_twist_scaled.push(Complex64::new(tr, -ti) * scale);
        }

        let scratch_a = UnsafeCell::new(vec![Complex64::new(0.0, 0.0); half_n]);
        let scratch_b = UnsafeCell::new(vec![Complex64::new(0.0, 0.0); half_n]);
        let fft_scratch = UnsafeCell::new(vec![Complex64::new(0.0, 0.0); fft_scratch_len]);

        Ok(Self {
            log_n,
            poly_length: n,
            fourier_length: half_n,
            fft_half,
            ifft_half,
            roots_re,
            roots_im,
            roots_half,
            twist_re,
            twist_im,
            inv_twist_scaled,
            scratch_a,
            scratch_b,
            fft_scratch,
        })
    }

    #[inline]
    fn poly_length(&self) -> usize {
        self.poly_length
    }

    #[inline]
    fn fourier_length(&self) -> usize {
        self.fourier_length
    }

    fn forward_torus_slice<T: TorusFftValue>(&self, input: &[T], output: &mut [f64]) {
        let n = self.poly_length;
        let half_n = self.fourier_length;
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(output.len(), 2 * half_n);

        // SAFETY: caller guarantees no concurrent access.
        let scratch_a = unsafe { &mut *self.scratch_a.get() };
        let scratch_b = unsafe { &mut *self.scratch_b.get() };
        let fft_scratch = unsafe { &mut *self.fft_scratch.get() };

        for m in 0..half_n {
            let tr = self.twist_re[m];
            let ti = self.twist_im[m];
            let even = input[2 * m].into_f64_centered();
            let odd = input[2 * m + 1].into_f64_centered();

            scratch_a[m].re = even * tr;
            scratch_a[m].im = even * ti;
            scratch_b[m].re = odd * tr;
            scratch_b[m].im = odd * ti;
        }

        self.fft_half.process_with_scratch(scratch_a, fft_scratch);
        self.fft_half.process_with_scratch(scratch_b, fft_scratch);

        combine_split(
            scratch_a,
            scratch_b,
            &self.roots_re,
            &self.roots_im,
            output,
            half_n,
        );
    }

    fn forward_centered_f64_slice(&self, input: &[f64], output: &mut [f64]) {
        let n = self.poly_length;
        let half_n = self.fourier_length;
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(output.len(), 2 * half_n);

        // SAFETY: caller guarantees no concurrent access.
        let scratch_a = unsafe { &mut *self.scratch_a.get() };
        let scratch_b = unsafe { &mut *self.scratch_b.get() };
        let fft_scratch = unsafe { &mut *self.fft_scratch.get() };

        for m in 0..half_n {
            let tr = self.twist_re[m];
            let ti = self.twist_im[m];
            let even = input[2 * m];
            let odd = input[2 * m + 1];

            scratch_a[m].re = even * tr;
            scratch_a[m].im = even * ti;
            scratch_b[m].re = odd * tr;
            scratch_b[m].im = odd * ti;
        }

        self.fft_half.process_with_scratch(scratch_a, fft_scratch);
        self.fft_half.process_with_scratch(scratch_b, fft_scratch);

        combine_split(
            scratch_a,
            scratch_b,
            &self.roots_re,
            &self.roots_im,
            output,
            half_n,
        );
    }

    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[f64], output: &mut [T]) {
        let n = self.poly_length;
        let half_n = self.fourier_length;
        debug_assert_eq!(input.len(), 2 * half_n);
        debug_assert_eq!(output.len(), n);

        // SAFETY: caller guarantees no concurrent access.
        let scratch_a = unsafe { &mut *self.scratch_a.get() };
        let scratch_b = unsafe { &mut *self.scratch_b.get() };
        let fft_scratch = unsafe { &mut *self.fft_scratch.get() };

        let (re, im) = input.split_at(half_n);
        for k in 0..half_n {
            let pk = Complex64::new(re[k], im[k]);
            let conj_partner = Complex64::new(re[half_n - 1 - k], -im[half_n - 1 - k]);

            scratch_a[k] = (pk + conj_partner) * 0.5;
            let diff = pk - conj_partner;
            scratch_b[k] = diff * self.roots_half[k].conj() * 0.5;
        }

        self.ifft_half.process_with_scratch(scratch_a, fft_scratch);
        self.ifft_half.process_with_scratch(scratch_b, fft_scratch);

        for m in 0..half_n {
            let even = (scratch_a[m] * self.inv_twist_scaled[m]).re;
            let odd = (scratch_b[m] * self.inv_twist_scaled[m]).re;
            output[2 * m] = T::from_f64_wrapping_rounded(even);
            output[2 * m + 1] = T::from_f64_wrapping_rounded(odd);
        }
    }
}

#[inline]
fn combine_split(
    scratch_a: &[Complex64],
    scratch_b: &[Complex64],
    roots_re: &[f64],
    roots_im: &[f64],
    output: &mut [f64],
    half_n: usize,
) {
    let (re, im) = output.split_at_mut(half_n);
    for k in 0..half_n {
        let ar = scratch_a[k].re;
        let ai = scratch_a[k].im;
        let br = scratch_b[k].re;
        let bi = scratch_b[k].im;
        let rr = roots_re[k];
        let ri = roots_im[k];

        re[k] = ar + rr * br - ri * bi;
        im[k] = ai + rr * bi + ri * br;
    }
}
