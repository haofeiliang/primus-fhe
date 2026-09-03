use thiserror::Error;

/// Errors that may occur during FFT table construction or operations.
#[derive(Error, Debug)]
pub enum FftError {
    /// The requested `log_n` is outside the supported range.
    ///
    /// A table requires `2 <= log_n <= usize::BITS - 1`.
    #[error("log_n {log_n} is invalid; must be in 2..={max}")]
    InvalidLogN {
        /// The requested log2(N).
        log_n: u32,
        /// The maximum allowed value.
        max: u32,
    },
}
