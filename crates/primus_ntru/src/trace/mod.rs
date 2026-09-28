//! Trace, normalized reverse trace, coefficient projection and expansion.

mod fourier;
mod kernels;
mod ntt;

pub use fourier::{FourierNtruTraceKey, FourierNtruTraceWorkspace};
pub use ntt::{NttNtruTraceKey, NttNtruTraceWorkspace};
