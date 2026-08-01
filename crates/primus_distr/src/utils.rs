//! Shared numerical utilities used by Gaussian sampler implementations.

use std::cmp::Ordering;

/// Returns the magnitude selected by a CDT with an inclusive terminal sentinel.
///
/// The first entry is the lower sentinel and the last entry is the maximum
/// random word. The terminal word belongs to the final supported magnitude,
/// rather than introducing an additional magnitude past the table's support.
#[inline(always)]
pub(crate) fn cdt_index_by<T>(
    cdt: &[T],
    random: &T,
    mut compare: impl FnMut(&T, &T) -> Ordering,
) -> usize {
    debug_assert!(cdt.len() >= 2);

    let upper = cdt.partition_point(|bound| compare(bound, random).is_le());
    debug_assert!(upper > 0);

    upper.saturating_sub(1).min(cdt.len().saturating_sub(2))
}

/// Log-sum-exp trick: compute `ln(Σ exp(x_i))` stably.
///
/// Avoids floating-point underflow when summing very small probabilities
/// represented in log-space.
pub(crate) fn log_sum_exp(log_values: &[f64]) -> f64 {
    if log_values.is_empty() {
        return f64::NEG_INFINITY;
    }
    let max_log = log_values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    if max_log.is_infinite() && max_log.is_sign_negative() {
        return f64::NEG_INFINITY;
    }
    let sum_exp: f64 = log_values
        .iter()
        .map(|&log_val| (log_val - max_log).exp())
        .sum();
    max_log + sum_exp.ln()
}

#[cfg(test)]
mod tests {
    use super::{cdt_index_by, log_sum_exp};

    #[test]
    fn terminal_sentinel_maps_to_last_supported_index() {
        let cdt = [0_u8, 2, 5, u8::MAX];

        assert_eq!(cdt_index_by(&cdt, &u8::MAX, Ord::cmp), cdt.len() - 2);
    }

    #[test]
    fn log_sum_exp_handles_separated_and_equal_values() {
        let separated = log_sum_exp(&[-1000.0, -1100.0, -1200.0]);
        assert!((separated + 1000.0).abs() < 1e-30);

        let equal = log_sum_exp(&[0.0, 0.0, 0.0]);
        assert!((equal - 3.0f64.ln()).abs() < 1e-10);

        let moderate = log_sum_exp(&[-1000.0, -1001.0, -1002.0]);
        let expected = -1000.0 + (1.0 + (-1.0f64).exp() + (-2.0f64).exp()).ln();
        assert!((moderate - expected).abs() < 1e-10);
    }
}
