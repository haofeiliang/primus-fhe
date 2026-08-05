//! Core types and operations for lattice-based homomorphic encryption.
//!
//! The public API is grouped by mathematical family. Use [`lwe`] for LWE,
//! [`glwe`] for single-modulus GLWE and RLWE.

#![deny(missing_docs)]

mod ciphertext;
mod error;
mod parameter;
mod rlwe;
mod secret_key_type;

pub mod glwe;
pub mod lwe;
pub mod plaintext;

pub use error::FheError;
pub use secret_key_type::SecretKeyDistr;

// Keep implementation imports concise without exposing the former flat public
// facade. These names are visible only inside this crate.
pub(crate) use ciphertext::*;
pub(crate) use glwe::*;
pub(crate) use lwe::*;
pub(crate) use parameter::*;
pub(crate) use plaintext::*;
pub(crate) use rlwe::*;
pub(crate) use secret_key_type::{SecretCoefficient, encode_secret_coefficient};
