//! High-precision lookup on independently encrypted, least-significant-first chunks.
//!
//! Compile a [`HighPrecisionLookupTable`] with [`LookupTableConfig`], then bind a
//! `NttLookupTableEvaluator` or `FourierLookupTableEvaluator` to a context,
//! return parameters and CBS-enabled server key. Reuse its workspace with caller-owned LWE outputs.
//! Input chunks are already encrypted; this crate does not split a single LWE.
//! The runnable `ntt_lookup` and `fourier_lookup` examples demonstrate key
//! generation, chunk encryption, table compilation, workspace reuse and decoding.
//! The Fourier example selects one concrete FFT table implementation.
//! With a backend enabled, both prepare complete `HighPrecLutParameters` from an
//! `experimental` lookup config: CBS, return, checked chunk layout and q/Q codecs.
//! Preparation does not enumerate the function, create keys or build a transform table.
//!
//! The common chunk radix is M=t/2, where t is the input codec’s plaintext modulus.
//! Coefficients encode output chunks at ring Q, using unsigned Rounded encoding.
//! After encrypted table selection and negative rotation, the existing return
//! key rescales Q to q and switches to the independent external LWE secret.
//! Output chunks use the same radix but an independently chosen count.
//! [`ChunkFormat`] derives that radix and the padded plaintext modulus from a
//! bit width, and optionally splits/joins cleartext words in reusable slices.
//!
//! # Compile without a backend
//! Only the ring length, accumulator Q, input codec at q and chunk geometry are
//! needed. No encryption parameters, keys or transform tables are constructed.
//!
//! ```
//! use primus_encoding::RoundedCodec;
//! use primus_modulus::{BarrettModulus, PowOf2Modulus};
//! use primus_poly::PolyLength;
//! use primus_tfhe_ntru_lut::{ChunkFormat, HighPrecisionLookupTable, LookupTableConfig};
//!
//! let chunks = ChunkFormat::new(2);
//! let codec = RoundedCodec::new(chunks.plaintext_modulus(), PowOf2Modulus::new(1u32 << 24));
//! let table = HighPrecisionLookupTable::try_new(
//!     PolyLength::new(32), BarrettModulus::new(65_537), &codec,
//!     LookupTableConfig {
//!         input_chunk_count: 3,
//!         output_chunk_count: 1,
//!         coefficient_chunk_count: 2,
//!     },
//!     |x, _| chunks.chunk(x, 0) as u32,
//! )?;
//! assert_eq!(table.stats().input_bits, 6);
//! assert_eq!(table.stats().unique_polynomial_count, 1);
//! # Ok::<(), primus_tfhe_ntru_lut::LookupTableError>(())
//! ```
//!
//! [`HighPrecisionLookupTable::stats`] describes the pruned selection plan;
//! [`HighPrecisionLookupTable::estimate_workspace`] estimates direct LUT buffers
//! for a chosen CBS output level count. See [`LookupWorkspaceEstimate`] for
//! the excluded resources. Evaluator binding separately validates N/q/Q and CBS.
//!
//! # Features
//! NTT is enabled by default. With `--no-default-features`, public table compilation
//! and inspection need no transform or evaluator. `ntt` / `fourier` enable the corresponding evaluator;
//! `fourier` is generic over an FFT table without choosing its implementation.
//! Either backend feature also enables `HighPrecisionLookupTable::try_from_parameters`,
//! which compiles with existing N/Q/q parameters without needing a context or keys.
//! The same features enable `experimental` paired u64 key/chunk configurations;
//! those arithmetic examples have no assessed security or failure-probability guarantee.
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

mod chunk;
#[cfg(any(feature = "ntt", feature = "fourier"))]
mod config;
#[cfg(any(feature = "ntt", feature = "fourier"))]
mod evaluation;
#[cfg(any(feature = "ntt", feature = "fourier"))]
pub mod experimental;
#[cfg(feature = "fourier")]
mod fourier;
mod lookup_table;
#[cfg(feature = "ntt")]
mod ntt;

pub use chunk::{ChunkFormat, ChunkFormatError};
#[cfg(any(feature = "ntt", feature = "fourier"))]
pub use config::{HighPrecLutConfig, HighPrecLutParameterError, HighPrecLutParameters};
#[cfg(feature = "fourier")]
pub use fourier::{FourierLookupTableEvaluator, FourierPublicLift};
pub use lookup_table::{
    HighPrecisionLookupTable, LookupTableConfig, LookupTableError, LookupTableStats,
    LookupWorkspaceEstimate,
};
#[cfg(feature = "ntt")]
pub use ntt::{NttLookupTableEvaluator, NttPublicLift};
