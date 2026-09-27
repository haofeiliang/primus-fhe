//! High-precision lookup on independently encrypted, least-significant-first chunks.
//!
//! Compile a [`HighPrecisionLookupTable`] with [`LookupTableConfig`], then bind a
//! [`NttLookupTableEvaluator`] or [`FourierLookupTableEvaluator`] to a CBS-enabled
//! context and server key. Reuse its workspace with caller-owned LWE outputs.
//! Input chunks are already encrypted; this crate does not split a single LWE.
//!
//! The common chunk radix is M=t/2, where t is the TFHE plaintext modulus.
//! Coefficients encode output chunks at ring Q, using unsigned Rounded encoding.
//! After encrypted table selection and negative rotation, the existing return
//! key rescales Q to q and switches to the independent external LWE secret.
//! Output chunks use the same radix but an independently chosen count.
//!
//! # Correctness
//! Every input must satisfy the one-hot CBS quantized-phase guard. Decoding also
//! needs a joint budget for CBS, public lifting, subsequent gadget products,
//! aggregated rotations and the Q-to-q return. Fourier adds FFT and native trace
//! rounding. Constructors validate shapes and encodings, not security or noise.

#![deny(missing_docs)]

mod fourier;
mod lookup_table;
mod ntt;

pub use fourier::FourierLookupTableEvaluator;
pub use lookup_table::{HighPrecisionLookupTable, LookupTableConfig, LookupTableError};
pub use ntt::NttLookupTableEvaluator;
