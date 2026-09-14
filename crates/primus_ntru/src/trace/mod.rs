//! Trace, normalized reverse trace, coefficient projection and expansion.

mod fourier;
mod kernels;
mod ntt;

pub use fourier::{FourierNtruTraceContext, FourierNtruTraceKey};
pub use ntt::{NttNtruTraceContext, NttNtruTraceKey};
