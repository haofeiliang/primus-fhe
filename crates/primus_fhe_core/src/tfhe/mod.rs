//! Backend-neutral TFHE parameters, client keys, ciphertexts, lookup tables,
//! and Boolean evaluation helpers.

mod backend;
mod boolean;
mod client;
mod error;
mod key;
mod lookup_table;
mod parameters;

pub use backend::*;
pub use client::{Ciphertext, Decryptor, Encryptor, TfheClientError};
pub use error::TfheEvaluationError;
pub use key::{ClientKey, LweSecretKeyRef, TfheKeyError};
pub use lookup_table::{LookupTable, LookupTableError};
pub use parameters::{PbsOrder, TfheParameterError, TfheParameters};

pub use boolean::{
    BOOLEAN_PLAINTEXT_BITS, BooleanCiphertext, BooleanDecryptor, BooleanEncryptor, BooleanError,
    BooleanEvaluator, BooleanGate, ProgrammableBootstrap,
};
