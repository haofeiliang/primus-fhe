use rand::Rng;

use super::GaussianParameters;
use crate::utils::{cdt_index_by, log_sum_exp};

/// Portable CDT implementation shared by signed and modular output adapters.
#[derive(Debug, Clone)]
pub(crate) struct CdtMagnitudeSampler {
    standard_deviation: f64,
    cdt: Vec<u64>,
}

impl CdtMagnitudeSampler {
    pub(crate) fn new(parameters: GaussianParameters) -> Self {
        let standard_deviation = parameters.standard_deviation();
        let length = parameters.maximum_magnitude() as usize + 1;
        let two_variance = 2.0 * standard_deviation * standard_deviation;

        let mut log_pdf = vec![f64::NEG_INFINITY; length];
        log_pdf[0] = 0.5f64.ln();
        for (magnitude, log_probability) in log_pdf.iter_mut().enumerate().skip(1) {
            let magnitude = magnitude as f64;
            *log_probability = -(magnitude * magnitude) / two_variance;
        }

        let log_sum = log_sum_exp(&log_pdf);
        let mut cdt = Vec::with_capacity(length + 1);
        let mut cumulative_probability = 0.0;
        cdt.push(0);

        for log_probability in log_pdf {
            cumulative_probability += (log_probability - log_sum).exp();
            let scaled = cumulative_probability.min(1.0) * u64::MAX as f64;
            cdt.push(if scaled >= u64::MAX as f64 {
                u64::MAX
            } else {
                (scaled + 0.5) as u64
            });
        }

        *cdt.last_mut().expect("CDT always has a terminal entry") = u64::MAX;
        debug_assert_eq!(cdt.len(), length + 1);

        Self {
            standard_deviation,
            cdt,
        }
    }

    #[inline]
    pub(crate) fn standard_deviation(&self) -> f64 {
        self.standard_deviation
    }

    #[inline]
    pub(crate) fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> (bool, usize) {
        let random = rng.next_u64();
        let positive = random & 1 == 1;
        let magnitude = cdt_index_by(&self.cdt, &random, Ord::cmp);
        (positive, magnitude)
    }
}
