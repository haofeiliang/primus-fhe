//! Representation-independent building blocks for TFHE execution backends.
//!
//! Choose [`LookupTable`] for one function, [`InterleavedLookupTable`] for several
//! Rounded outputs, [`FactorizedLookupTable`] for Scaled MVB programs, or
//! [`BivariateLookupTable`] to pack bounded inputs. Backends prepare tables/keys and
//! execute these programs; this crate does not own a transform context or server key.
//! [`BooleanEvaluator`] composes the small PBS traits for Boolean gate evaluation.
//!
//! [`Encryptor`], [`Decryptor`] and their Boolean wrappers share external LWE
//! workflows through [`LweClientParameters`], without a transform backend.
//!
//! Raw PBS inputs and outputs use [`LweCiphertext`] directly. Encoding and
//! Boolean evaluators bind encoding and reusable workspace around these raw values.

#![deny(missing_docs)]

mod boolean;
mod bootstrap;
mod client;
mod error;
mod lookup_table;
mod parameters;

pub mod rotation;
pub mod sparse;

pub use boolean::{BOOLEAN_PLAINTEXT_BITS, BooleanEvaluator, BooleanGate};
pub use bootstrap::{ProgrammableBootstrap, ProgrammableBootstrapInterleaved};
pub use client::{
    BooleanDecryptor, BooleanEncryptor, BooleanError, ClientError, Decryptor, EncryptionKey,
    Encryptor, LweClientParameters,
};
pub use error::{LookupTableError, TfheEvaluationError};
pub use lookup_table::{
    BivariateLookupTable, FactorizedLookupTable, InterleavedLookupTable, LookupTable,
    front_half_domain_len,
};
pub use parameters::CircuitBootstrapConfig;
pub use primus_decompose::DecompositionConfig;
pub use primus_lwe::{LweCiphertext, LweSecretKeyRef};
