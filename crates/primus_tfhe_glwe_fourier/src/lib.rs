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

use primus_modulus::NativeModulus;

mod blind_rotation;
mod bootstrapping_key;
mod context;
mod error;
mod evaluator;
mod key;

pub mod boolean;

pub use error::{
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};

pub use blind_rotation::FourierGlweBlindRotationContext;
pub use bootstrapping_key::FourierGlweBootstrappingKey;
pub use context::TfheContext;
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};
pub use primus_tfhe::{LookupTable, LweCiphertext, LweSecretKeyRef, ManyLookupTable};
pub use primus_tfhe_glwe::{GlweClientKey as ClientKey, GlwePbsOrder as PbsOrder};

pub use boolean::{
    BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};

/// Encryptor role for the native-torus Fourier backend.
///
/// Accepts the client secret key or an external LWE public key.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_glwe::GlweEncryptor<'a, T, NativeModulus<T>, NativeModulus<T>, Key>;

/// Client-key decryptor for the native-torus Fourier backend.
pub type Decryptor<'a, T> =
    primus_tfhe_glwe::GlweDecryptor<'a, T, NativeModulus<T>, NativeModulus<T>>;

/// GLWE-TFHE parameters for the native-torus Fourier backend.
pub type TfheParameters<T> =
    primus_tfhe_glwe::GlweTfheParameters<T, NativeModulus<T>, NativeModulus<T>>;
