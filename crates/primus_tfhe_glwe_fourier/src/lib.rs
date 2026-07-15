//! Fourier backend for GLWE-based TFHE.

pub mod boolean;
mod client;
mod context;
pub mod error;
mod evaluator;
mod key;
pub mod parameters;

// Common TFHE API.
pub use client::{Decryptor, Encryptor};
pub use context::TfheContext;
pub use error::{
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use parameters::TfheParameters;
pub use primus_fhe_core::{Ciphertext, ClientKey, LookupTable, LweKeySwitchingParameters};

// Boolean API. Keep this group separate from future high-level APIs such as
// `small_int`.
pub use boolean::{
    BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};
