//! Backend-neutral GLWE-based TFHE parameters, client keys, ciphertexts, and
//! lookup-table workflows.
//!
//! # Public-key clients
//!
//! [`GlweClientKey::try_generate_public_key`] returns an [`LwePublicKey`] under
//! the external client secret: small LWE for bootstrap-then-key-switch, or the
//! signed GLWE coefficient vector for key-switch-then-bootstrap. Pass the public
//! key to [`GlweEncryptor::try_new`] or [`BooleanEncryptor::new`]; keep the client
//! key for decryption. NTT/Fourier contexts also accept it in `encryptor`.
//! The `Key` parameter selects secret/public encryption at compile time, sharing
//! message checks and encoding APIs. It does not change the PBS output domain.
//!
//! Public-key identity and combined-noise requirements are documented on
//! [`GlweEncryptionKey`]; generation parameters and storage size are documented
//! on [`GlweClientKey::try_generate_public_key`].

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
pub use client::{GlweClientError, GlweDecryptor, GlweEncryptionKey, GlweEncryptor};
pub use key::{GlweClientKey, GlweKeyError};
pub use parameters::{GlweParameterError, GlwePbsOrder, GlweTfheParameters};

pub use primus_tfhe::{
    LookupTable, LookupTableError, LweCiphertext, LweSecretKeyRef, ManyLookupTable,
    ProgrammableBootstrap, ProgrammableBootstrapMany, TfheEvaluationError,
};

pub use primus_glwe::SecretKeyDistr;

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;
