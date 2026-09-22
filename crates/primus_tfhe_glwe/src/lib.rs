//! Backend-neutral GLWE-based TFHE parameters, client keys, ciphertexts, and
//! lookup-table workflows.
//!
//! [`ClientKey::generate`] creates coefficient-domain client secrets without
//! transform tables. Backend contexts generate paired client/server keys.
//!
//! # Role in the backend workflow
//!
//! [`TfheConfig`] names mathematical choices; [`TfheParameters`] validates them and
//! compiles Rounded LUTs. [`ClientKey`], [`Encryptor`] and [`Decryptor`] bind client
//! secrets and encoding. Choose the NTT/Fourier backend for transform tables,
//! server material and evaluators. [`KeyGenerationError`] and [`TfheClientError`]
//! report key generation and family client construction; operations return
//! shared [`ClientError`] or [`BooleanError`].
//!
//! # Public-key clients
//!
//! [`ClientKey::try_generate_public_key`] returns an [`LwePublicKey`] under
//! the external client secret: small LWE for bootstrap-then-key-switch, or the
//! signed GLWE coefficient vector for key-switch-then-bootstrap. Pass the public
//! key to [`TfheParameters::public_encryptor`]; keep the client key for decryption.
//! NTT/Fourier contexts provide `public_encryptor` and `boolean_public_encryptor`.
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

mod circuit_bootstrap;
mod client;
mod error;
mod key;
mod lookup_table;
mod parameters;

use primus_glwe::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, GlweSecretKey,
};
use primus_lwe::{LweParameters, LweSecretKey};

pub use circuit_bootstrap::CircuitBootstrapParameters;
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};
pub use key::ClientKey;
pub use parameters::{PbsOrder, TfheConfig, TfheParameters};

pub use primus_tfhe::{
    BOOLEAN_PLAINTEXT_BITS, BivariateLookupTable, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate, CircuitBootstrapConfig, ClientError, DecompositionConfig,
    Decryptor, EncryptionKey, Encryptor, InterleavedLookupTable, LookupTable, LookupTableError,
    LweCiphertext, LweSecretKeyRef, ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
    TfheEvaluationError,
};

pub use primus_glwe::SecretKeyDistr;

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;
