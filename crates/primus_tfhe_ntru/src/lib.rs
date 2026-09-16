//! Backend-independent client API and parameters for NTRU-based TFHE.
//!
//! # Public-key clients
//!
//! [`NtruClientKey::try_generate_public_key`] returns an [`LwePublicKey`] under
//! the active binary prefix of the client secret. Pass it to
//! [`NtruEncryptor::try_new`] or a backend context's `encryptor`; keep the paired
//! client key for decryption.
//!
//! Public-key identity and combined-noise requirements are documented on
//! [`NtruEncryptionKey`]; generation parameters and storage size are documented
//! on [`NtruClientKey::try_generate_public_key`].
//!
//! # Reusing client ciphertext storage
//!
//! [`NtruEncryptor::encrypt_to`], [`NtruEncryptor::encrypt_padded_to`] and
//! [`NtruEncryptor::encrypt_centered_to`] overwrite an existing [`LweCiphertext`]
//! without allocating, for either secret or public keys. Message and dimension
//! errors leave output and RNG unchanged. Backend `Encryptor` aliases expose
//! these same methods.

#![deny(missing_docs)]

mod client;
mod key;
mod lookup_table;
mod parameters;

pub use client::{NtruClientError, NtruDecryptor, NtruEncryptionKey, NtruEncryptor};
pub use key::{NtruClientKey, NtruKeyError};
pub use parameters::{NtruParameterError, NtruTfheParameters};

pub use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey};
pub use primus_tfhe::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, LookupTableError, LweCiphertext,
    LweSecretKeyRef, ProgrammableBootstrap, ProgrammableBootstrapInterleaved, TfheEvaluationError,
};

/// LWE public key used by the public-key client encryptor.
pub use primus_lwe::LwePublicKey;
