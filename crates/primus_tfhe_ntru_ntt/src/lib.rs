//! Exact NTT backend for NTRU-based TFHE.

#![deny(missing_docs)]

mod bootstrapping_key;
mod client;
mod context;
mod error;
mod evaluator;
mod key;
mod parameters;

pub use client::{Decryptor, Encryptor};
pub use context::TfheContext;
pub use error::{
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use parameters::TfheParameters;

pub use primus_tfhe::{Ciphertext, LookupTable, LweSecretKeyRef};
pub use primus_tfhe_ntru::{NtruClientKey as ClientKey, NtruTfheParameters};
