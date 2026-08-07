//! Fourier backend for GLWE-based TFHE.

#![deny(missing_docs)]

mod error;

mod bootstrapping_key;
mod client;
mod context;
mod evaluator;
mod key;

mod parameters;

pub mod boolean;

// Common TFHE API.
pub use error::{
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};

pub use bootstrapping_key::{FourierGlweBlindRotationContext, FourierGlweBootstrappingKey};
pub use client::{Decryptor, Encryptor};
pub use context::TfheContext;
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use primus_tfhe::{Ciphertext, LookupTable, LweSecretKeyRef};
pub use primus_tfhe_glwe::{GlweClientKey as ClientKey, GlwePbsOrder as PbsOrder};

pub use parameters::TfheParameters;

// Boolean API. Keep this group separate from future high-level APIs such as
// `small_int`.
pub use boolean::{
    BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};
