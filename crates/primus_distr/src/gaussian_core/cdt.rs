use super::GaussianParameters;
use crate::utils::log_sum_exp;

/// Builds the portable CDT shared by signed and modular output adapters.
#[inline(always)]
pub(crate) fn build_cdt(parameters: GaussianParameters) -> (f64, Vec<u64>) {
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
    let normalized_log_pdf: Vec<f64> = log_pdf
        .iter()
        .map(|&log_probability| log_probability - log_sum)
        .collect();
    let normalized_pdf: Vec<f64> = normalized_log_pdf
        .iter()
        .map(|&log_probability| log_probability.exp())
        .collect();

    let mut cdt = Vec::with_capacity(length + 1);
    let mut cumulative_probability = 0.0;
    cdt.push(0);

    for &probability in normalized_pdf.iter() {
        cumulative_probability += probability;
        let scaled = cumulative_probability.min(1.0) * u64::MAX as f64;
        cdt.push(if scaled >= u64::MAX as f64 {
            u64::MAX
        } else {
            (scaled + 0.5) as u64
        });
    }

    if let Some(last) = cdt.last_mut() {
        *last = u64::MAX;
    }
    assert_eq!(cdt.len(), length + 1, "CDT length mismatch");

    (standard_deviation, cdt)
}
