//! Fourier backend for GLWE-based TFHE.

pub mod boolean;
mod client;
mod context;
mod evaluator;
mod key;
pub mod parameters;

// Common TFHE API.
pub use client::{Decryptor, Encryptor};
pub use context::{TfheContext, TfheContextError};
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use parameters::TfheParameters;
pub use primus_fhe_core::{
    Ciphertext, ClientKey, LookupTable, LookupTableError, LweKeySwitchingParameters,
    TfheClientError, TfheEvaluationError, TfheKeyError, TfheParameterError,
};

// Boolean API. Keep this group separate from future high-level APIs such as
// `small_int`.
pub use boolean::{
    BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};
