//! Backend-neutral GLWE-based TFHE parameters, client keys, ciphertexts, and
//! lookup-table workflows.

#![deny(missing_docs)]

mod client;
mod key;
mod lookup_table;
mod parameters;

mod boolean;

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
use primus_glwe::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweSecretKey,
};
use primus_lwe::{LweParameters, LweSecretKey};

pub use boolean::{
    BOOLEAN_PLAINTEXT_BITS, BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate,
};
pub use client::{GlweClientError, GlweDecryptor, GlweEncryptor};
pub use key::{GlweClientKey, GlweKeyError};
pub use parameters::{GlweParameterError, GlwePbsOrder, GlweTfheParameters};

pub use primus_tfhe::{
    LookupTable, LookupTableError, LweCiphertext, LweSecretKeyRef, ManyLookupTable,
    ProgrammableBootstrap, ProgrammableBootstrapMany, TfheEvaluationError,
};

pub use primus_glwe::SecretKeyDistr;
