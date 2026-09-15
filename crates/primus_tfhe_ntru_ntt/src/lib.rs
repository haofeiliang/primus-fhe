//! Exact NTT backend for NTRU-based TFHE.
//!
//! [`Evaluator::apply_many_lookup_table_to`] evaluates interleaved outputs with
//! one blind rotation and ring key switch, reusing its existing workspace.
//! Compile with [`TfheContext::compile_many_lookup_table_fn`] or the input-major
//! slice variant. The output count is a non-zero power of two and reduces the
//! rotation resolution; [`ManyLookupTable`] describes the layout and noise tradeoff.
//! Public PBS checks LUT encoding/moduli/length and all output dimensions before
//! writing. Raw input key, encoding and noise remain caller requirements.

//! [`CircuitBootstrapEvaluator`] optionally keeps the BR accumulator under f_acc,
//! projects gadget-scaled outputs and converts NLev to NGSW. Its additional keys
//! and independent noise/security parameters are separate from ordinary PBS.

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
    LookupTableError, TfheClientError, TfheContextError, TfheEvaluationError, TfheKeyError,
    TfheParameterError,
};
pub use evaluator::Evaluator;
pub use key::{KeyGenerator, ServerKey};

pub use primus_tfhe::{LookupTable, LweCiphertext, LweSecretKeyRef, ManyLookupTable};
pub use primus_tfhe_ntru::{NtruClientKey as ClientKey, NtruTfheParameters};

pub use circuit_bootstrap::{
    CircuitBootstrapEvaluationError, CircuitBootstrapEvaluator, CircuitBootstrapKey,
    CircuitBootstrapKeyError, CircuitBootstrapParameterError, CircuitBootstrapParameters,
};

/// Secret-key or LWE public-key encryptor for the exact NTT NTRU backend.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_ntru::NtruEncryptor<'a, T, BarrettModulus<T>, Key>;

/// Client-key decryptor for the exact NTT NTRU backend.
pub type Decryptor<'a, T> = primus_tfhe_ntru::NtruDecryptor<'a, T, BarrettModulus<T>>;

/// NTRU-TFHE parameters for the explicit-modulus NTT backend.
pub type TfheParameters<T> = primus_tfhe_ntru::NtruTfheParameters<T, BarrettModulus<T>>;
