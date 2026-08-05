//! Core types and operations for lattice-based homomorphic encryption.
//!
//! The public API is grouped by mathematical family. Use [`lwe`] for LWE.

#![deny(missing_docs)]

mod ciphertext;
mod error;
mod parameter;
mod secret_key_type;

pub mod lwe;
pub mod plaintext;

pub use error::FheError;
pub use secret_key_type::{SecretCoefficient, SecretKeyDistr};

// Keep implementation imports concise without exposing the former flat public
// facade. These names are visible only inside this crate.
pub(crate) use ciphertext::*;
pub(crate) use lwe::*;
pub(crate) use parameter::*;
pub(crate) use plaintext::*;
pub(crate) use secret_key_type::encode_secret_coefficient;
