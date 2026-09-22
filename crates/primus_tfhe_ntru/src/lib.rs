//! Backend-independent client API and parameters for NTRU-based TFHE.
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
//! the active binary or ternary prefix of the client secret. Pass it to
//! [`TfheParameters::public_encryptor`] or a backend context's `public_encryptor`; keep the paired
//! client key for decryption.
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

pub use circuit_bootstrap::CircuitBootstrapParameters;
pub use error::{
    CircuitBootstrapParameterError, KeyGenerationError, SparseBootstrappingKeyError,
    TfheClientError, TfheKeyError, TfheParameterError,
};
pub use key::ClientKey;
pub use parameters::{TfheConfig, TfheParameters};

pub use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey};
pub use primus_tfhe::{
    BOOLEAN_PLAINTEXT_BITS, BivariateLookupTable, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate, CircuitBootstrapConfig, ClientError, DecompositionConfig,
    Decryptor, EncryptionKey, Encryptor, InterleavedLookupTable, LookupTable, LookupTableError,
    LweCiphertext, LweSecretKeyRef, ProgrammableBootstrap, ProgrammableBootstrapInterleaved,
    TfheEvaluationError,
};

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;
