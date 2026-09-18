//! Exact NTT backend for NTRU-based TFHE.
//!
//! [`Evaluator::apply_interleaved_lookup_table_to`] evaluates interleaved outputs with
//! one blind rotation and ring key switch, reusing its existing workspace.
//! Compile through [`TfheParameters::compile_interleaved_lookup_table_fn`] or its
//! input-major slice variant. The next power of two of the output count determines the
//! rotation step; [`InterleavedLookupTable`] describes the layout and noise tradeoff.
//! Public PBS checks LUT encoding/moduli/length and all output dimensions before
//! writing. Raw input key, encoding and noise remain caller requirements.

//! [`CircuitBootstrapEvaluator`] optionally keeps the BR accumulator under f_acc,
//! projects gadget-scaled outputs and converts NLev to NGSW. Select its additional
//! keys and independent noise parameters with [`CircuitBootstrapConfig`] during key
//! generation, then bind the evaluator from the resulting [`ServerKey`].

#![deny(missing_docs)]

use primus_modulus::BarrettModulus;

mod blind_rotation;
mod circuit_bootstrap;
mod context;
mod error;
mod evaluator;
mod key;

pub use context::TfheContext;
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, LookupTableError, TfheClientError,
    TfheContextError, TfheEvaluationError, TfheKeyError, TfheParameterError,
};
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};

pub use primus_tfhe::{
    BivariateLookupTable, CircuitBootstrapConfig, DecompositionConfig, InterleavedLookupTable,
    LookupTable, LweCiphertext, LweSecretKeyRef,
};
pub use primus_tfhe_ntru::{ClientKey, EncryptionKey, LwePublicKey};

pub use circuit_bootstrap::{
    CircuitBootstrapEvaluator, CircuitBootstrapKey, CircuitBootstrapParameters,
};

/// Secret-key or LWE public-key encryptor for the exact NTT NTRU backend.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_ntru::Encryptor<'a, T, BarrettModulus<T>, Key>;

/// Client-key decryptor for the exact NTT NTRU backend.
pub type Decryptor<'a, T> = primus_tfhe_ntru::Decryptor<'a, T, BarrettModulus<T>>;

/// NTRU-TFHE parameters for the explicit-modulus NTT backend.
pub type TfheParameters<T> = primus_tfhe_ntru::TfheParameters<T, BarrettModulus<T>>;

/// Named mathematical choices for this backend; moduli are derived from the LWE parameters.
pub type TfheConfig<T> = primus_tfhe_ntru::TfheConfig<T, BarrettModulus<T>>;
