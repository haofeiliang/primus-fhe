//! NTT backend for GLWE-based TFHE.

pub mod error;

mod client;
mod context;
mod evaluator;
mod key;

pub mod parameters;

pub mod boolean;

// Common TFHE API.
pub use error::{
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};

pub use client::{Decryptor, Encryptor};
pub use context::TfheContext;
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use primus_fhe_core::{Ciphertext, ClientKey, LookupTable, LweSecretKeyRef, PbsOrder};

pub use parameters::TfheParameters;

// Boolean API. Keep this group separate from future high-level APIs such as
// `small_int`.
pub use boolean::{
    BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};
pub use parameters::boolean_parameters;
