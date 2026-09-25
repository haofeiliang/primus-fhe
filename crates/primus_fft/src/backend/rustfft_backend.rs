use std::{f64::consts::PI, sync::Arc};

use aligned_vec::{ABox, AVec, CACHELINE_ALIGN, avec};
use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FftError, FftTable, TorusFftValue};

/// Reusable workspace for [`RustFftTable`].
/// The full, fixed-length buffers are securely erased on drop.
/// Explicit zeroization preserves lengths and allocations for reuse.
pub struct RustFftScratch {
    values: ABox<[Complex64]>,
    fft: ABox<[Complex64]>,
}

impl Zeroize for RustFftScratch {
    fn zeroize(&mut self) {
        for buffer in [&mut self.values, &mut self.fft] {
            // Complex64 has no Zeroize implementation. Erase both components
            // while preserving the lengths required by the plan. The boxed
            // slices have no spare capacity outside these initialized elements.
            for value in buffer.iter_mut() {
                value.re.zeroize();
                value.im.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for RustFftScratch {}

impl Drop for RustFftScratch {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Negacyclic FFT wrapper backed by RustFFT.
/// Owned twist and scratch buffers use cache-line alignment. Caller-owned
/// slices only need their element type's normal alignment.
pub struct RustFftTable {
    n: usize,
    h: usize,
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
    twist: ABox<[Complex64]>,
    inverse_twist_scaled: ABox<[Complex64]>,
}

impl RustFftTable {
    fn forward_with<T: Copy>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        convert: impl Fn(T) -> f64,
        scratch: &mut RustFftScratch,
    ) {
        assert_eq!(input.len(), self.n);
        assert_eq!(output.len(), self.h);
        let (first, second) = input.split_at(self.h);
        for (((output, &re), &im), &twist) in output
            .iter_mut()
            .zip(first)
            .zip(second)
            .zip(self.twist.iter())
        {
            *output = Complex64::new(convert(re), convert(im)) * twist;
        }
        self.forward.process_with_scratch(output, &mut scratch.fft);
    }
}

impl FftTable for RustFftTable {
    type Scratch = RustFftScratch;

    fn new(log_n: u32) -> Result<Self, FftError> {
        if !(2..usize::BITS).contains(&log_n) {
            return Err(FftError::InvalidLogN {
                log_n,
                max: usize::BITS - 1,
            });
        }
        let n = 1usize << log_n;
        let h = n / 2;
        let mut planner = FftPlanner::new();
        let forward = planner.plan_fft_forward(h);
        let inverse = planner.plan_fft_inverse(h);
        let twist = AVec::from_iter(
            CACHELINE_ALIGN,
            (0..h).map(|j| Complex64::cis(PI * j as f64 / n as f64)),
        )
        .into_boxed_slice();
        let inverse_twist_scaled = AVec::from_iter(
            CACHELINE_ALIGN,
            (0..h).map(|j| Complex64::cis(-PI * j as f64 / n as f64) / h as f64),
        )
        .into_boxed_slice();
        Ok(Self {
            n,
            h,
            forward,
            inverse,
            twist,
            inverse_twist_scaled,
        })
    }

    fn poly_length(&self) -> usize {
        self.n
    }
    fn fourier_length(&self) -> usize {
        self.h
    }

    fn automorphism_map(&self, degree: usize) -> Vec<(usize, bool)> {
        crate::automorphism::automorphism_map(self.n, degree, core::convert::identity)
    }

    fn new_scratch(&self) -> Self::Scratch {
        let scratch_len = self
            .forward
            .get_inplace_scratch_len()
            .max(self.inverse.get_inplace_scratch_len());
        RustFftScratch {
            values: avec![Complex64::default(); self.h].into_boxed_slice(),
            fft: avec![Complex64::default(); scratch_len].into_boxed_slice(),
        }
    }

    fn forward_as_torus<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        scratch: &mut Self::Scratch,
    ) {
        self.forward_with(input, output, TorusFftValue::into_torus_f64, scratch);
    }

    fn forward_as_integer<T: TorusFftValue>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        scratch: &mut Self::Scratch,
    ) {
        self.forward_with(input, output, TorusFftValue::into_signed_f64, scratch);
    }

    fn forward_integer_f64(
        &self,
        input: &[f64],
        output: &mut [Complex64],
        scratch: &mut Self::Scratch,
    ) {
        self.forward_with(input, output, core::convert::identity, scratch);
    }

    fn backward_as_torus<T: TorusFftValue>(
        &self,
        input: &[Complex64],
        output: &mut [T],
        scratch: &mut Self::Scratch,
    ) {
        assert_eq!(input.len(), self.h);
        assert_eq!(output.len(), self.n);
        let RustFftScratch { values, fft } = scratch;
        values.copy_from_slice(input);
        self.inverse.process_with_scratch(values, fft);
        let (first, second) = output.split_at_mut(self.h);
        for ((&value, &inverse_twist), (first, second)) in values
            .iter()
            .zip(self.inverse_twist_scaled.iter())
            .zip(first.iter_mut().zip(second))
        {
            let value = value * inverse_twist;
            *first = T::from_torus_f64(value.re);
            *second = T::from_torus_f64(value.im);
        }
    }
}
