//! Native-torus Fourier backend for NTRU-based TFHE.
//!
//! [`Evaluator::apply_many_lookup_table_to`] evaluates interleaved outputs with
//! one blind rotation and ring key switch, reusing its existing workspace.
//! Compile with [`TfheContext::compile_many_lookup_table_fn`] or the input-major
//! slice variant. The output count is a non-zero power of two and reduces the
//! rotation resolution; [`ManyLookupTable`] describes the layout and noise tradeoff.
//! Public PBS checks LUT encoding/moduli/length and all output dimensions before
//! writing. Raw input key, encoding and noise remain caller requirements.

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

pub use primus_tfhe::{LookupTable, LweCiphertext, LweSecretKeyRef, ManyLookupTable};
pub use primus_tfhe_ntru::{NtruClientKey as ClientKey, NtruTfheParameters};
