#![deny(missing_docs)]
//! Negacyclic FFT wrappers for `Z[X] / (X^N + 1)`.

mod error;
mod table;
mod torus;

mod backend;

/// CPU feature detection used by downstream optimized kernels.
pub mod cpu;

pub use error::FftError;
pub use num_complex::Complex64;
pub use table::FftTable;
pub use torus::TorusFftValue;

pub use backend::{RustFftTable, TfheFftTable};
