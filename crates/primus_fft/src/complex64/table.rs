use std::cell::UnsafeCell;
use std::f64::consts::PI;
use std::sync::Arc;

use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};

use crate::error::FftError;
use crate::table::FftTable;
use crate::torus::TorusFftValue;

/// Negacyclic FFT table backed by `rustfft` with split `[re | im]` output.
///
/// Uses a pre-allocated `Complex64` scratch buffer (guarded by [`UnsafeCell`])
/// so no heap allocation occurs in the hot path.  The scratch is shared across
/// calls — the methods take `&self` (not `&mut self`) for thread-safety of
/// the read-only pre-computed tables, but the caller must ensure that no two
/// threads concurrently call `forward_torus_slice` / `inverse_torus_slice` on
/// the same table instance.
pub struct FftTableImpl {
    log_n: u32,
    poly_length: usize,
    fourier_length: usize,
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
    twist: Vec<Complex64>,
    inv_twist_scaled: Vec<Complex64>,
    /// Pre-allocated scratch (length = fourier_length).  Wrapped in
    /// [`UnsafeCell`] so the `&self` methods can mutate it.
    scratch: UnsafeCell<Vec<Complex64>>,
    /// Scratch required by rustfft plans.
    fft_scratch: UnsafeCell<Vec<Complex64>>,
}

// Safety: the scratch buffer is only accessed from `&self` methods that are
// never called concurrently on the same instance.  (The trait requires
// `Send + Sync` so the table can be *shared*; concurrent *use* must be
// synchronised externally.)
unsafe impl Sync for FftTableImpl {}

impl FftTableImpl {
    /// Returns `log2(N)`.
    #[inline]
    pub fn log_n(&self) -> u32 {
        self.log_n
    }
}

impl FftTable for FftTableImpl {
    fn new(log_n: u32) -> Result<Self, FftError> {
        if log_n >= usize::BITS {
            return Err(FftError::InvalidLogN {
                log_n,
                max: usize::BITS - 1,
            });
        }

        let n = 1usize << log_n;

        let mut planner = FftPlanner::new();
        let forward = planner.plan_fft_forward(n);
        let inverse = planner.plan_fft_inverse(n);
        let fft_scratch_len = forward
            .get_inplace_scratch_len()
            .max(inverse.get_inplace_scratch_len());

        let n_f64 = n as f64;
        let twist: Vec<Complex64> = (0..n)
            .map(|j| Complex64::cis(PI * j as f64 / n_f64))
            .collect();

        let inv_twist_scaled: Vec<Complex64> = (0..n)
            .map(|j| Complex64::cis(-PI * j as f64 / n_f64) / n_f64)
            .collect();

        let scratch = UnsafeCell::new(vec![Complex64::new(0.0, 0.0); n]);
        let fft_scratch = UnsafeCell::new(vec![Complex64::new(0.0, 0.0); fft_scratch_len]);

        Ok(Self {
            log_n,
            poly_length: n,
            fourier_length: n,
            forward,
            inverse,
            twist,
            inv_twist_scaled,
            scratch,
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
        debug_assert_eq!(input.len(), self.poly_length);
        let m = self.fourier_length;
        debug_assert_eq!(output.len(), 2 * m);

        // SAFETY: caller guarantees no concurrent access.
        let scratch = unsafe { &mut *self.scratch.get() };
        let fft_scratch = unsafe { &mut *self.fft_scratch.get() };

        // Step 1: center + twist → Complex64 scratch.
        for (j, &val) in input.iter().enumerate() {
            let centered = val.into_f64_centered();
            scratch[j] = Complex64::new(centered, 0.0) * self.twist[j];
        }

        // Step 2: in-place FFT on scratch.
        self.forward.process_with_scratch(scratch, fft_scratch);

        // Step 3: gather → split [re | im] output.
        let (re, im) = output.split_at_mut(m);
        for (j, c) in scratch.iter().enumerate() {
            re[j] = c.re;
            im[j] = c.im;
        }
    }

    fn forward_centered_f64_slice(&self, input: &[f64], output: &mut [f64]) {
        debug_assert_eq!(input.len(), self.poly_length);
        let m = self.fourier_length;
        debug_assert_eq!(output.len(), 2 * m);

        // SAFETY: caller guarantees no concurrent access.
        let scratch = unsafe { &mut *self.scratch.get() };
        let fft_scratch = unsafe { &mut *self.fft_scratch.get() };

        // Step 1: twist only (values already centered f64) → Complex64 scratch.
        for (j, &val) in input.iter().enumerate() {
            scratch[j] = Complex64::new(val, 0.0) * self.twist[j];
        }

        // Step 2: in-place FFT on scratch.
        self.forward.process_with_scratch(scratch, fft_scratch);

        // Step 3: gather → split [re | im] output.
        let (re, im) = output.split_at_mut(m);
        for (j, c) in scratch.iter().enumerate() {
            re[j] = c.re;
            im[j] = c.im;
        }
    }

    fn inverse_torus_slice<T: TorusFftValue>(&self, input: &[f64], output: &mut [T]) {
        let m = self.fourier_length;
        debug_assert_eq!(input.len(), 2 * m);
        debug_assert_eq!(output.len(), self.poly_length);

        // SAFETY: caller guarantees no concurrent access.
        let scratch = unsafe { &mut *self.scratch.get() };
        let fft_scratch = unsafe { &mut *self.fft_scratch.get() };

        // Step 1: scatter split [re | im] → Complex64 scratch.
        let (re, im) = input.split_at(m);
        for (j, c) in scratch.iter_mut().enumerate() {
            c.re = re[j];
            c.im = im[j];
        }

        // Step 2: in-place inverse FFT.
        self.inverse.process_with_scratch(scratch, fft_scratch);

        // Step 3: untwist + round.
        for (j, val) in scratch.iter().enumerate() {
            let v = *val * self.inv_twist_scaled[j];
            output[j] = T::from_f64_wrapping_rounded(v.re);
        }
    }
}
