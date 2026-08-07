//! Backend-independent client API and parameters for NTRU-based TFHE.

#![deny(missing_docs)]

mod client;
mod key;
mod lookup_table;
mod parameters;

pub use client::{NtruClientError, NtruDecryptor, NtruEncryptor};
pub use key::{NtruClientKey, NtruKeyError};
pub use parameters::{NtruParameterError, NtruTfheParameters};

pub use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey};
pub use primus_tfhe::{
    Ciphertext, LookupTable, LookupTableError, LweSecretKeyRef, ProgrammableBootstrap,
    TfheEvaluationError,
};
