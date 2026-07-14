use std::{f64::consts::PI, time::Duration};

use dyn_stack::{PodBuffer, PodStack};
use num_complex::Complex64;
use tfhe_fft::unordered::{Method, Plan};

use crate::{FftError, FftTable, TorusFftValue};

/// Negacyclic FFT wrapper backed by the unordered tfhe-fft plan.
pub struct TfheFftTable {
    n: usize,
    h: usize,
    plan: Plan,
    twist: Vec<Complex64>,
    inverse_twist_scaled: Vec<Complex64>,
}

/// Reusable workspace for [`TfheFftTable`].
pub struct TfheFftScratch {
    values: Vec<Complex64>,
    memory: PodBuffer,
}

impl TfheFftTable {
    fn forward_with<T: Copy>(
        &self,
        input: &[T],
        output: &mut [Complex64],
        convert: impl Fn(T) -> f64,
        scratch: &mut TfheFftScratch,
    ) {
        assert_eq!(input.len(), self.n);
        assert_eq!(output.len(), self.h);
        let (first, second) = input.split_at(self.h);
        for (((output, &re), &im), &twist) in
            output.iter_mut().zip(first).zip(second).zip(&self.twist)
        {
            *output = Complex64::new(convert(re), convert(im)) * twist;
        }
        self.plan.fwd(output, PodStack::new(&mut scratch.memory));
    }
}

impl FftTable for TfheFftTable {
    type Scratch = TfheFftScratch;

    fn new(log_n: u32) -> Result<Self, FftError> {
        if !(2..usize::BITS).contains(&log_n) {
            return Err(FftError::InvalidLogN {
                log_n,
                max: usize::BITS - 1,
            });
        }
        let n = 1usize << log_n;
        let h = n / 2;
        let plan = Plan::new(h, Method::Measure(Duration::from_millis(10)));
        let twist = (0..h)
            .map(|j| Complex64::cis(PI * j as f64 / n as f64))
            .collect();
        let inverse_twist_scaled = (0..h)
            .map(|j| Complex64::cis(-PI * j as f64 / n as f64) / h as f64)
            .collect();
        Ok(Self {
            n,
            h,
            plan,
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

    fn new_scratch(&self) -> Self::Scratch {
        TfheFftScratch {
            values: vec![Complex64::default(); self.h],
            memory: PodBuffer::try_new(self.plan.fft_scratch())
                .expect("failed to allocate FFT scratch"),
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
        scratch.values.copy_from_slice(input);
        let TfheFftScratch { values, memory } = scratch;
        self.plan.inv(values, PodStack::new(memory));
        let (first, second) = output.split_at_mut(self.h);
        for ((&value, &inverse_twist), (first, second)) in values
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
