#![deny(missing_docs)]
//! Torus negacyclic FFT transforms for `Z[X] / (X^N + 1)`.
//!
//! Provides the [`FftTable`] trait and the [`FftTableImpl`] backend backed by
//! the `rustfft` crate with pre-allocated scratch. The forward transform
//! centres torus coefficients, applies a negacyclic twist, performs a complex
//! FFT, and gathers the result into split `[re | im]` f64 layout.
//!
//! # Fourier data layout
//!
//! Fourier buffers use a split real/imaginary format:
//! `[re_0, ..., re_{m-1}, im_0, ..., im_{m-1}]` where `m = fourier_length()`.
//! Total buffer size is `buffer_len() = 2 * fourier_length()`.

/// FFT backend backed by `rustfft` with pre-allocated scratch.
pub mod complex64;
pub mod cpu;
mod error;
/// Packed negacyclic FFT backend (rustfft-backed reference, `fourier_length = N/2`).
pub mod packed64;
mod table;
mod torus;

pub use complex64::FftTableImpl;
pub use error::FftError;
pub use packed64::PackedFftTable;
pub use table::FftTable;
pub use torus::TorusFftValue;
