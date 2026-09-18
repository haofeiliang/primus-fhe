//! NTT backend for GLWE-based TFHE.
//!
//! [`Evaluator::apply_interleaved_lookup_table_to`] evaluates interleaved outputs with
//! one blind rotation and ring key switch, reusing its existing workspace.
//! Compile through [`TfheContext::parameters`] using
//! [`TfheParameters::compile_interleaved_lookup_table_fn`] or the input-major slice variant. The next power of two of the output count determines the
//! rotation step; [`InterleavedLookupTable`] describes the layout and noise tradeoff.
//! Public PBS checks LUT encoding/moduli/length and all output dimensions before
//! writing. Raw input key, encoding and noise remain caller requirements.
//!
//! [`TfheContext::compile_factorized_lookup_table_fn`] prepares fixed-scale MVB
//! for [`FactorizedEvaluator`]: one BR at step one, followed by per-output
//! polynomial products and extraction/KS. [`NttFactorizedLookupTable`] borrows
//! the preparing context; outputs use the supplied [`primus_encoding::ScaledCodec`].
//!
//! [`KeyGenerator::try_generate_sparse_bootstrapping_key`] builds an experimental
//! [`SparseGlweBootstrappingKey`] with public buckets and encrypted selections.
//! Its raw LUT blind rotation reuses [`SparseGlweBlindRotationContext`].
//! [`KeyGenerator::try_generate_sparse_server_key`] integrates this path with
//! [`Evaluator`] for ordinary and interleaved PBS in both orders.
//!
//! Use [`TfheContext::boolean_encryptor`], [`TfheContext::boolean_decryptor`] and
//! [`TfheContext::boolean_evaluator`] to bind Boolean operations to the same
//! context (`t = 4`). Create the evaluator once, then reuse output storage with
//! [`BooleanEvaluator::evaluate_binary_to`], [`BooleanEvaluator::not_to`] and
//! [`BooleanEvaluator::mux_to`].

#![deny(missing_docs)]

use primus_modulus::BarrettModulus;

mod accumulator;
mod blind_rotation;
mod bootstrapping_key;
mod circuit_bootstrap;
mod context;
mod error;
mod evaluator;
mod key;
mod parameters;
mod sparse;

pub mod boolean;

pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, LookupTableError,
    SparseBootstrappingKeyError, TfheClientError, TfheContextError, TfheEvaluationError,
    TfheKeyError, TfheParameterError,
};

pub use accumulator::AccumulatorClient;
pub use blind_rotation::NttGlweBlindRotationContext;
pub use bootstrapping_key::NttGlweBootstrappingKey;
pub use circuit_bootstrap::{
    CircuitBootstrapEvaluator, CircuitBootstrapKey, CircuitBootstrapParameters,
};
pub use context::TfheContext;
pub use evaluator::{Evaluator, FactorizedEvaluator, NttFactorizedLookupTable};
pub use key::{BootstrappingKey, KeyGenerator, ServerKey};
pub use parameters::{TfheParameters, boolean_parameters};
pub use primus_tfhe::{
    BivariateLookupTable, CircuitBootstrapConfig, DecompositionConfig, FactorizedLookupTable,
    InterleavedLookupTable, LookupTable, LweCiphertext, LweSecretKeyRef,
};
pub use primus_tfhe_glwe::{ClientKey, EncryptionKey, PbsOrder};
pub use sparse::{SparseGlweBlindRotationContext, SparseGlweBootstrappingKey};

pub use boolean::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator, BooleanGate,
};

/// Encryptor role for the explicit-modulus NTT backend.
///
/// Accepts the client secret key or an external LWE public key.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_glwe::Encryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>, Key>;

/// Client-key decryptor for the explicit-modulus NTT backend.
pub type Decryptor<'a, T> =
    primus_tfhe_glwe::Decryptor<'a, T, BarrettModulus<T>, BarrettModulus<T>>;

/// Named mathematical choices for this backend; moduli are derived from the LWE parameters.
pub type TfheConfig<T> = primus_tfhe_glwe::TfheConfig<T, BarrettModulus<T>>;
