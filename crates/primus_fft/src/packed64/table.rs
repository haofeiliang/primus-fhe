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
/// Uses a decimation-in-frequency (DIF) decomposition: the real `N`-point
/// polynomial is split into even and odd parts, each of length `N/2`.  Two
/// `N/2`-point FFTs produce the half-length Fourier representation
/// `P_k = Σ a_j * exp(iπ(2k+1)j/N)` for `k = 0..N/2-1`.
///
/// The inverse reconstructs the full evaluation via conjugate symmetry,
/// then runs two `N/2`-point inverse FFTs in decimation-in-time (DIT) style.
///
/// # Scratch buffers
///
/// Pre-allocated scratch is guarded by [`UnsafeCell`] — same safety contract as
/// [`crate::complex64::FftTableImpl`]: the caller must not call the transform
/// methods concurrently on the same instance.
pub struct PackedFftTable {
    log_n: u32,
    poly_length: usize,
    fourier_length: usize,
    /// N/2-point FFT (rustfft inverse planner: exp(+i…) convention).
    fft_half: Arc<dyn Fft<f64>>,
    /// N/2-point FFT (rustfft forward planner: exp(−i…) convention).
    ifft_half: Arc<dyn Fft<f64>>,
    /// `ω_k = exp(iπ(2k+1)/N)` for `k = 0..N/2-1`.
    roots_half: Vec<Complex64>,
    /// `ψ_m = exp(i2πm/N)` for `m = 0..N/2-1` (split twist for even/odd).
    twist_split: Vec<Complex64>,
    /// `ψ_m^{-1} = exp(-i2πm/N)` for `m = 0..N/2-1` (inverse split twist).
    inv_twist_split: Vec<Complex64>,
    /// Scratch for even part (length N/2).
    scratch_a: UnsafeCell<Vec<Complex64>>,
    /// Scratch for odd part (length N/2).
    scratch_b: UnsafeCell<Vec<Complex64>>,
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
        // N must be at least 4 so N/2 >= 2 (rustfft requires length >= 2).
        if log_n < 2 {
            return Err(FftError::InvalidLogN {
                log_n,
                max: usize::BITS - 1,
            });
        }

        let n = 1usize << log_n;
        let half_n = n / 2;

        let mut planner = FftPlanner::new();
        // Swapped: use "inverse" planner to get exp(+i2πkn/N') sign in the
        // forward DIF decomposition, and "forward" planner for the DIT inverse.
        let fft_half = planner.plan_fft_inverse(half_n);
        let ifft_half = planner.plan_fft_forward(half_n);

        let n_f64 = n as f64;

        let roots_half: Vec<Complex64> = (0..half_n)
            .map(|k| Complex64::cis(PI * (2 * k + 1) as f64 / n_f64))
            .collect();

        let twist_split: Vec<Complex64> = (0..half_n)
            .map(|m| Complex64::cis(2.0 * PI * m as f64 / n_f64))
            .collect();

        let inv_twist_split: Vec<Complex64> = (0..half_n)
            .map(|m| Complex64::cis(-2.0 * PI * m as f64 / n_f64))
            .collect();

        let scratch_a = UnsafeCell::new(vec![Complex64::new(0.0, 0.0); half_n]);
        let scratch_b = UnsafeCell::new(vec![Complex64::new(0.0, 0.0); half_n]);

        Ok(Self {
            log_n,
            poly_length: n,
            fourier_length: half_n,
            fft_half,
            ifft_half,
            roots_half,
            twist_split,
            inv_twist_split,
            scratch_a,
            scratch_b,
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

        // Step 1: split even/odd and twist.
        //   b'_m = centered(a_{2m})   * exp(i2πm/N)
        //   c'_m = centered(a_{2m+1}) * exp(i2πm/N)
        for m in 0..half_n {
            let even = input[2 * m].into_f64_centered();
            let odd = input[2 * m + 1].into_f64_centered();
            scratch_a[m] = Complex64::new(even, 0.0) * self.twist_split[m];
            scratch_b[m] = Complex64::new(odd, 0.0) * self.twist_split[m];
        }

        // Step 2: N/2-point FFT on each part (uses "inverse" planner for +i sign).
        self.fft_half.process(scratch_a);
        self.fft_half.process(scratch_b);

        // Step 3: combine — P_k = B_k + ω_k * C_k.
        // Store in split [re | im] layout.
        let (re, im) = output.split_at_mut(half_n);
        for k in 0..half_n {
            let p = scratch_a[k] + self.roots_half[k] * scratch_b[k];
            re[k] = p.re;
            im[k] = p.im;
        }
    }

    fn forward_centered_f64_slice(&self, input: &[f64], output: &mut [f64]) {
        let n = self.poly_length;
        let half_n = self.fourier_length;
        debug_assert_eq!(input.len(), n);
        debug_assert_eq!(output.len(), 2 * half_n);

        // SAFETY: caller guarantees no concurrent access.
        let scratch_a = unsafe { &mut *self.scratch_a.get() };
        let scratch_b = unsafe { &mut *self.scratch_b.get() };

        // Step 1: split even/odd and twist (values already centered f64).
        for m in 0..half_n {
            scratch_a[m] = Complex64::new(input[2 * m], 0.0) * self.twist_split[m];
            scratch_b[m] = Complex64::new(input[2 * m + 1], 0.0) * self.twist_split[m];
        }

        // Step 2: N/2-point FFT on each part.
        self.fft_half.process(scratch_a);
        self.fft_half.process(scratch_b);

        // Step 3: combine — P_k = B_k + ω_k * C_k.
        let (re, im) = output.split_at_mut(half_n);
        for k in 0..half_n {
            let p = scratch_a[k] + self.roots_half[k] * scratch_b[k];
            re[k] = p.re;
            im[k] = p.im;
        }
    }

    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[f64], output: &mut [T]) {
        let n = self.poly_length;
        let half_n = self.fourier_length;
        debug_assert_eq!(input.len(), 2 * half_n);
        debug_assert_eq!(output.len(), n);

        // SAFETY: caller guarantees no concurrent access.
        let scratch_a = unsafe { &mut *self.scratch_a.get() };
        let scratch_b = unsafe { &mut *self.scratch_b.get() };

        let (re, im) = input.split_at(half_n);
        let scale = 1.0 / (half_n as f64);

        // Step 1: recover B_k and C_k from P_k using conjugate symmetry:
        //   B_k = (P_k + conj(P_{N/2-1-k})) / 2
        //   C_k = (P_k - conj(P_{N/2-1-k})) / (2 * ω_k)
        for k in 0..half_n {
            let pk = Complex64::new(re[k], im[k]);
            let conj_partner = Complex64::new(re[half_n - 1 - k], -im[half_n - 1 - k]);

            scratch_a[k] = (pk + conj_partner) * 0.5;
            let diff = pk - conj_partner;
            // diff / (2 * ω_k) = diff * conj(ω_k) / (2 * |ω_k|²) = diff * conj(ω_k) / 2
            // since |ω_k| = 1.
            scratch_b[k] = diff * self.roots_half[k].conj() * 0.5;
        }

        // Step 2: N/2-point inverse FFT on B and C (uses "forward" planner for −i sign).
        // rustfft forward FFT is unnormalized, so output is (N/2)× too large.
        self.ifft_half.process(scratch_a);
        self.ifft_half.process(scratch_b);

        // Step 3: untwist and round.
        //   a_{2m}   = Re[b'_m * exp(-i2πm/N)]
        //   a_{2m+1} = Re[c'_m * exp(-i2πm/N)]
        // Both are scaled by N/2 (from the unnormalized FFT), so divide.
        for m in 0..half_n {
            let even = (scratch_a[m] * self.inv_twist_split[m] * scale).re;
            let odd = (scratch_b[m] * self.inv_twist_split[m] * scale).re;
            output[2 * m] = T::from_f64_wrapping_rounded(even);
            output[2 * m + 1] = T::from_f64_wrapping_rounded(odd);
        }
    }
}
