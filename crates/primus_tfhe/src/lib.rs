//! Representation-independent building blocks for TFHE execution backends.
//!
//! Raw PBS inputs and outputs use [`LweCiphertext`] directly. Encoding and
//! higher-level state belong to semantic wrappers such as Boolean ciphertexts.

#![deny(missing_docs)]

mod bivariate_lookup_table;
mod bootstrap;
mod error;
mod lookup_table;

#[doc(hidden)]
pub mod backend_support;

pub use bivariate_lookup_table::BivariateLookupTable;
pub use bootstrap::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
pub use error::{LookupTableError, TfheEvaluationError};
pub use lookup_table::{InterleavedLookupTable, LookupTable, lookup_table_domain_len};
pub use primus_lwe::{LweCiphertext, LweSecretKeyRef};
