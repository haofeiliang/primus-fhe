use std::{
    f64::consts::PI,
    sync::{Arc, Mutex},
};

use num_complex::Complex64;
use rustfft::{Fft, FftPlanner};

use crate::{FftError, FftTable, TorusFftValue};

struct Scratch {
    values: Vec<Complex64>,
    fft: Vec<Complex64>,
}

/// Negacyclic FFT wrapper backed by RustFFT.
pub struct RustFftTable {
    n: usize,
    h: usize,
    forward: Arc<dyn Fft<f64>>,
    inverse: Arc<dyn Fft<f64>>,
    twist: Vec<Complex64>,
    inverse_twist_scaled: Vec<Complex64>,
    scratch: Mutex<Scratch>,
}

impl RustFftTable {
    fn forward_with<T: Copy>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        convert: impl Fn(T) -> f64,
    ) {
        assert_eq!(input.len(), self.n);
        assert_eq!(output.len(), self.h);
        let (first, second) = input.split_at(self.h);
        for (((output, &re), &im), &twist) in
            output.iter_mut().zip(first).zip(second).zip(&self.twist)
        {
            *output = Complex64::new(convert(re), convert(im)) * twist;
        }
        let mut scratch = self.scratch.lock().expect("FFT scratch mutex poisoned");
        self.forward.process_with_scratch(output, &mut scratch.fft);
    }
}

impl FftTable for RustFftTable {
    fn new(log_n: u32) -> Result<Self, FftError> {
        if log_n < 2 || log_n >= usize::BITS {
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
        let scratch_len = forward
            .get_inplace_scratch_len()
            .max(inverse.get_inplace_scratch_len());
        let twist = (0..h)
            .map(|j| Complex64::cis(PI * j as f64 / n as f64))
            .collect();
        let inverse_twist_scaled = (0..h)
            .map(|j| Complex64::cis(-PI * j as f64 / n as f64) / h as f64)
            .collect();
        Ok(Self {
            n,
            h,
            forward,
            inverse,
            twist,
            inverse_twist_scaled,
            scratch: Mutex::new(Scratch {
                values: vec![Complex64::default(); h],
                fft: vec![Complex64::default(); scratch_len],
            }),
        })
    }

    fn poly_length(&self) -> usize {
        self.n
    }
    fn fourier_length(&self) -> usize {
        self.h
    }

    fn forward_as_torus<T: TorusFftValue>(&self, input: &[T], output: &mut [Complex64]) {
        self.forward_with(input, output, TorusFftValue::into_torus_f64);
    }

    fn forward_as_integer<T: TorusFftValue>(&self, input: &[T], output: &mut [Complex64]) {
        self.forward_with(input, output, TorusFftValue::into_signed_f64);
    }

    fn forward_integer_f64(&self, input: &[f64], output: &mut [Complex64]) {
        self.forward_with(input, output, core::convert::identity);
    }

    fn backward_as_torus<T: TorusFftValue>(&self, input: &[Complex64], output: &mut [T]) {
        assert_eq!(input.len(), self.h);
        assert_eq!(output.len(), self.n);
        let mut scratch = self.scratch.lock().expect("FFT scratch mutex poisoned");
        let Scratch { values, fft } = &mut *scratch;
        values.copy_from_slice(input);
        self.inverse.process_with_scratch(values, fft);
        let (first, second) = output.split_at_mut(self.h);
        for ((&value, &inverse_twist), (first, second)) in scratch
            .values
            .iter()
            .zip(&self.inverse_twist_scaled)
            .zip(first.iter_mut().zip(second))
        {
            let value = value * inverse_twist;
            *first = T::from_torus_f64(value.re);
            *second = T::from_torus_f64(value.im);
        }
    }
}
