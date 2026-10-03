//! High-precision lookup on independently encrypted, least-significant-first chunks.
//!
//! Compile a [`HighPrecisionLookupTable`] with [`LookupTableConfig`], then bind a
//! `NttLookupTableEvaluator` or `FourierLookupTableEvaluator` to a CBS-enabled
//! context and server key. Reuse its workspace with caller-owned LWE outputs.
//! Input chunks are already encrypted; this crate does not split a single LWE.
//! The runnable `ntt_lookup` and `fourier_lookup` examples demonstrate key
//! generation, chunk encryption, table compilation, workspace reuse and decoding.
//! The Fourier example selects one concrete FFT table implementation.
//!
//! The common chunk radix is M=t/2, where t is the TFHE plaintext modulus.
//! Coefficients encode output chunks at ring Q, using unsigned Rounded encoding.
//! After encrypted table selection and negative rotation, the existing return
//! key rescales Q to q and switches to the independent external LWE secret.
//! Output chunks use the same radix but an independently chosen count.
//!
//! # Features
//! Default features are empty: public table compilation and inspection need no
//! transform or evaluator. `ntt` / `fourier` enable the corresponding evaluator;
//! `fourier` is generic over an FFT table without choosing its implementation.
//! `rustfft` / `tfhe-fft` enable `fourier` and the selected FFT implementation.
//! Features are additive. `simd` propagates nightly SIMD to active arithmetic
//! dependencies without activating an evaluator or FFT implementation.
//!
//! # Correctness
//! Every input must satisfy the one-hot CBS quantized-phase guard. Decoding also
//! needs a joint budget for CBS, public lifting, subsequent gadget products,
//! aggregated rotations and the Q-to-q return. Fourier adds FFT and native trace
//! rounding. Constructors validate shapes and encodings, not security or noise.

#![deny(missing_docs)]

#[cfg(any(feature = "ntt", feature = "fourier"))]
mod evaluation;
#[cfg(feature = "fourier")]
mod fourier;
mod lookup_table;
#[cfg(feature = "ntt")]
mod ntt;

#[cfg(feature = "fourier")]
pub use fourier::FourierLookupTableEvaluator;
pub use lookup_table::{HighPrecisionLookupTable, LookupTableConfig, LookupTableError};
#[cfg(feature = "ntt")]
pub use ntt::NttLookupTableEvaluator;
