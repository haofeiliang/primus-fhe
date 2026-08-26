//! Representation-independent building blocks for TFHE execution backends.

#![deny(missing_docs)]

mod bootstrap;
mod ciphertext;
mod error;
mod key;
mod lookup_table;

#[doc(hidden)]
pub mod backend_support;

pub use bootstrap::{ProgrammableBootstrap, ProgrammableBootstrapMany};
pub use ciphertext::{Ciphertext, TfheCiphertextError};
pub use error::TfheEvaluationError;
pub use key::LweSecretKeyRef;
pub use lookup_table::{
    LookupTable, LookupTableError, ManyLookupTable, compile_encoded_lookup_table,
    compile_encoded_many_lookup_table, lookup_table_domain_len,
};
