//! Native-torus Fourier backend for NTRU-based TFHE.
//!
//! [`Evaluator::apply_interleaved_lookup_table_to`] evaluates interleaved outputs with
//! one blind rotation and ring key switch, reusing its existing workspace.
//! Compile with [`TfheContext::compile_interleaved_lookup_table_fn`] or the input-major
//! slice variant. The next power of two of the output count determines the
//! rotation step; [`InterleavedLookupTable`] describes the layout and noise tradeoff.
//! Public PBS checks LUT encoding/moduli/length and all output dimensions before
//! writing. Raw input key, encoding and noise remain caller requirements.

//! [`CircuitBootstrapEvaluator`] optionally keeps the BR accumulator under f_acc,
//! projects gadget-scaled outputs and converts NLev to NGSW. Its additional keys
//! and independent noise/security parameters are separate from ordinary PBS.

#![deny(missing_docs)]

use primus_modulus::NativeModulus;

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

pub use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, LweCiphertext, LweSecretKeyRef,
};
pub use primus_tfhe_ntru::{NtruClientKey as ClientKey, NtruTfheParameters};

pub use circuit_bootstrap::{
    CircuitBootstrapEvaluationError, CircuitBootstrapEvaluator, CircuitBootstrapKey,
    CircuitBootstrapKeyError, CircuitBootstrapParameterError, CircuitBootstrapParameters,
};

/// Secret-key or LWE public-key encryptor for the Fourier NTRU backend.
pub type Encryptor<'a, T, Key = ClientKey<T>> =
    primus_tfhe_ntru::NtruEncryptor<'a, T, NativeModulus<T>, Key>;

/// Client-key decryptor for the Fourier NTRU backend.
pub type Decryptor<'a, T> = primus_tfhe_ntru::NtruDecryptor<'a, T, NativeModulus<T>>;

/// NTRU-TFHE parameters for the native-torus Fourier backend.
pub type TfheParameters<T> = primus_tfhe_ntru::NtruTfheParameters<T, NativeModulus<T>>;
