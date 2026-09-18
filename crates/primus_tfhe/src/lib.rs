//! Representation-independent building blocks for TFHE execution backends.
//!
//! Raw PBS inputs and outputs use [`LweCiphertext`] directly. Encoding and
//! Boolean evaluators bind encoding and reusable workspace around these raw values.

#![deny(missing_docs)]

mod boolean;
mod bootstrap;
mod error;
mod lookup_table;
mod parameters;

pub mod rotation;

pub use boolean::{BOOLEAN_PLAINTEXT_BITS, BooleanEvaluator, BooleanGate};
pub use bootstrap::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
pub use error::{LookupTableError, TfheEvaluationError};
pub use lookup_table::{
    BivariateLookupTable, FactorizedLookupTable, InterleavedLookupTable, LookupTable,
    front_half_domain_len,
};
pub use parameters::{CircuitBootstrapConfig, DecompositionConfig};
pub use primus_lwe::{LweCiphertext, LweSecretKeyRef};
