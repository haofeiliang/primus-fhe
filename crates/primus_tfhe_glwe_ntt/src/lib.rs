//! NTT backend for GLWE-based TFHE.
//!
//! [`Evaluator::apply_interleaved_lookup_table_to`] evaluates interleaved outputs with
//! one blind rotation and ring key switch, reusing its existing workspace.
//! Compile with [`TfheContext::compile_interleaved_lookup_table_fn`] or the input-major
//! slice variant. The next power of two of the output count determines the
//! rotation step; [`InterleavedLookupTable`] describes the layout and noise tradeoff.
//! Public PBS checks LUT encoding/moduli/length and all output dimensions before
//! writing. Raw input key, encoding and noise remain caller requirements.
//!
//! Use [`TfheContext::boolean_encryptor`], [`TfheContext::boolean_decryptor`] and
//! [`TfheContext::boolean_evaluator`] to bind Boolean operations to the same
//! context (`t = 4`). Create the evaluator once, then reuse output storage with
//! [`BooleanEvaluator::evaluate_binary_to`], [`BooleanEvaluator::not_to`] and
//! [`BooleanEvaluator::mux_to`].

#![deny(missing_docs)]

use primus_modulus::BarrettModulus;

mod blind_rotation;
mod bootstrapping_key;
mod circuit_bootstrap;
mod context;
mod error;
mod evaluator;
mod key;
mod parameters;

pub mod boolean;

pub use error::{
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};

pub use blind_rotation::NttGlweBlindRotationContext;
pub use bootstrapping_key::NttGlweBootstrappingKey;
pub use circuit_bootstrap::{
    CircuitBootstrapEvaluationError, CircuitBootstrapEvaluator, CircuitBootstrapKey,
    CircuitBootstrapKeyError, CircuitBootstrapParameterError, CircuitBootstrapParameters,
};
pub use context::TfheContext;
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use parameters::{TfheParameters, boolean_parameters};
pub use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, LweCiphertext, LweSecretKeyRef,
};
pub use primus_tfhe_glwe::{GlweClientKey as ClientKey, GlwePbsOrder as PbsOrder};

pub use boolean::{
    BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};

/// Encryptor role for the explicit-modulus NTT backend.
///
/// Accepts the client secret key or an external LWE public key.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_glwe::GlweEncryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>, Key>;

/// Client-key decryptor for the explicit-modulus NTT backend.
pub type Decryptor<'a, T> =
    primus_tfhe_glwe::GlweDecryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>>;
