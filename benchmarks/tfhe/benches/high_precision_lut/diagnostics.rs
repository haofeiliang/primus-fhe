//! Opt-in phase reporting for the existing lookup fixture, outside timed iterations.

/// Decrypts phases lazily only when `PRIMUS_LUT_DIAGNOSTICS=1` is set.
/// Expected values are raw two-bit digits; both backends use q=2^24 and padded t=8.
pub(super) fn report_phase_error(name: &str, phases: impl Iterator<Item = (u64, u64)>) {
    if !std::env::var_os("PRIMUS_LUT_DIAGNOSTICS").is_some_and(|value| value == "1") {
        return;
    }
    let max_error = phases
        .map(|(phase, digit)| {
            let distance = phase.abs_diff(digit * (1 << 21));
            distance.min((1 << 24) - distance)
        })
        .max()
        .unwrap_or(0);
    eprintln!("phase_error_max,{name},{max_error}");
}
