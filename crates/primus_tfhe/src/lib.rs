//! Representation-independent building blocks for TFHE execution backends.
//!
//! Raw PBS inputs and outputs use [`LweCiphertext`] directly. Encoding and
//! higher-level state belong to semantic wrappers such as Boolean ciphertexts.

#![deny(missing_docs)]

mod bootstrap;
mod error;
mod lookup_table;

#[doc(hidden)]
pub mod backend_support;

pub use bootstrap::{ProgrammableBootstrap, ProgrammableBootstrapMany};
pub use error::TfheEvaluationError;
pub use lookup_table::{
    LookupTable, LookupTableError, ManyLookupTable, compile_encoded_lookup_table,
    compile_encoded_many_lookup_table, lookup_table_domain_len,
};
pub use primus_lwe::{LweCiphertext, LweSecretKeyRef};
