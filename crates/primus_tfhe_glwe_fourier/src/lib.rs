//! Fourier backend for GLWE-based TFHE.
//!
//! [`Evaluator::apply_many_lookup_table_to`] evaluates interleaved outputs with
//! one blind rotation and ring key switch, reusing its existing workspace.
//! Compile with [`TfheContext::compile_many_lookup_table_fn`] or the input-major
//! slice variant. The output count is a non-zero power of two and reduces the
//! rotation resolution; [`ManyLookupTable`] describes the layout and noise tradeoff.
//! Public PBS checks LUT encoding/moduli/length and all output dimensions before
//! writing. Raw input key, encoding and noise remain caller requirements.
//!
//! Use [`TfheContext::boolean_encryptor`], [`TfheContext::boolean_decryptor`] and
//! [`TfheContext::boolean_evaluator`] to bind Boolean operations to the same
//! context (`t = 4`). Create the evaluator once, then reuse output storage with
//! [`BooleanEvaluator::evaluate_binary_to`], [`BooleanEvaluator::not_to`] and
//! [`BooleanEvaluator::mux_to`].

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
pub use primus_tfhe::{LookupTable, LweCiphertext, LweSecretKeyRef, ManyLookupTable};
pub use primus_tfhe_glwe::{GlweClientKey as ClientKey, GlwePbsOrder as PbsOrder};

pub use parameters::TfheParameters;

// Boolean API. Keep this group separate from future high-level APIs such as
// `small_int`.
pub use boolean::{
    BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};
