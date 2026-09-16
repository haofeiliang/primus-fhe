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

pub use bootstrap::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
pub use error::{LookupTableError, TfheEvaluationError};
pub use lookup_table::{
    BivariateLookupTable, InterleavedLookupTable, LookupTable, front_half_domain_len,
};
pub use primus_lwe::{LweCiphertext, LweSecretKeyRef};
