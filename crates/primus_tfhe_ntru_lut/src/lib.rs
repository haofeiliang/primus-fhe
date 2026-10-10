//! High-precision lookup on independently encrypted, least-significant-first chunks.
//!
//! With a backend enabled, `NttHighPrecLutContext` / `FourierHighPrecLutContext`
//! prepare the complete CBS/return/chunk operation and one transform environment.
//! Compile a pure integer function, generate its required public material, then
//! bind an evaluator and reuse caller-owned ciphertexts. The client adapters
//! split/join complete integers without digit buffers or hand-written codec wiring.
//! The runnable `ntt_lookup` and `fourier_lookup` examples show this workflow.
//! It still encrypts independent chunks; it does not split a single LWE homomorphically.
//!
//! `HighPrecLutParameters` can compile before constructing transforms. Context
//! construction moves that prepared owner without cloning samplers or creating
//! another BR domain. Compilation, key generation and workspace allocation are
//! separate explicit operations. Sparse generates independent `NLEV[1]` only
//! when there are no table-selection chunks (c=d); classic reuses its existing initializer.
//! Raw public compilation and explicit component evaluators remain available.
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
//! assert_eq!(table.input_value_count(), 64);
//! assert_eq!(table.polynomials_per_output(), 4);
//! # Ok::<(), primus_tfhe_ntru_lut::LookupTableError>(())
//! ```
//!
//! All logical polynomials are stored, and each output uses the complete selection
//! tree. Equal polynomials or repeated outputs do not change the work performed.
//! Evaluator binding separately validates N/q/Q and CBS, and checks buffer sizes
//! before allocating its workspace.
//!
//! # Features
//! NTT and RustFFT are enabled by default. Use
//! `--no-default-features --features tfhe-fft` for TFHE-FFT alone, or
//! `--features tfhe-fft` to add TFHE-FFT alongside the defaults.
//! With `--no-default-features`, public table compilation and inspection need no
//! transform or evaluator. `ntt` / `fourier` enable the corresponding Context and evaluator;
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
mod client;
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
pub use client::{HighPrecLutClientError, HighPrecLutDecryptor, HighPrecLutEncryptor};
#[cfg(any(feature = "ntt", feature = "fourier"))]
pub use config::{HighPrecLutConfig, HighPrecLutParameterError, HighPrecLutParameters};
#[cfg(feature = "fourier")]
pub use fourier::{
    FourierHighPrecLutContext, FourierHighPrecLutServerKey, FourierLookupTableEvaluator,
    FourierPublicLift, FourierPublicLiftKey,
};
pub use lookup_table::{HighPrecisionLookupTable, LookupTableConfig, LookupTableError};
#[cfg(feature = "ntt")]
pub use ntt::{
    NttHighPrecLutContext, NttHighPrecLutContextError, NttHighPrecLutServerKey,
    NttLookupTableEvaluator, NttPublicLift, NttPublicLiftKey,
};
