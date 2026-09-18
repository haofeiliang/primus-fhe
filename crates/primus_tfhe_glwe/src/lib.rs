//! Backend-neutral GLWE-based TFHE parameters, client keys, ciphertexts, and
//! lookup-table workflows.
//!
//! [`ClientKey::generate`] creates coefficient-domain client secrets without
//! transform tables. Backend contexts generate paired client/server keys.
//!
//! # Public-key clients
//!
//! [`ClientKey::try_generate_public_key`] returns an [`LwePublicKey`] under
//! the external client secret: small LWE for bootstrap-then-key-switch, or the
//! signed GLWE coefficient vector for key-switch-then-bootstrap. Pass the public
//! key to [`Encryptor::try_new`] or [`BooleanEncryptor::try_new`]; keep the client
//! key for decryption. NTT/Fourier contexts also accept it in `encryptor`.
//! The `Key` parameter selects secret/public encryption at compile time, sharing
//! message checks and encoding APIs. It does not change the PBS output domain.
//!
//! Public-key identity and combined-noise requirements are documented on
//! [`EncryptionKey`]; generation parameters and storage size are documented
//! on [`ClientKey::try_generate_public_key`].
//!
//! # Reusing client ciphertext storage
//!
//! [`Encryptor::encrypt_to`], [`Encryptor::encrypt_padded_to`] and
//! [`Encryptor::encrypt_centered_to`] overwrite an existing [`LweCiphertext`]
//! without allocating, for either secret or public keys. Message and dimension
//! errors leave output and RNG unchanged. Backend `Encryptor` aliases expose
//! these same methods.

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
    BOOLEAN_PLAINTEXT_BITS, BooleanDecryptor, BooleanEncryptor, BooleanError, BooleanEvaluator,
    BooleanGate,
};
pub use client::{Decryptor, EncryptionKey, Encryptor, TfheClientError};
pub use key::{ClientKey, TfheKeyError};
pub use parameters::{PbsOrder, TfheConfig, TfheParameterError, TfheParameters};

pub use primus_tfhe::{
    BivariateLookupTable, CircuitBootstrapConfig, DecompositionConfig, InterleavedLookupTable,
    LookupTable, LookupTableError, LweCiphertext, LweSecretKeyRef, ProgrammableBootstrap,
    ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

pub use primus_glwe::SecretKeyDistr;

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;
