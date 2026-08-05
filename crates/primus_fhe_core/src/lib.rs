//! Core types and operations for lattice-based homomorphic encryption.
//!
//! The public API is grouped by mathematical family. Use [`lwe`] for LWE,
//! [`glwe`] for single-modulus GLWE and RLWE, [`rns_fhe`] for CRT/DCRT and
//! Hybrid-RNS operations, and [`tfhe`] for the backend-neutral TFHE workflow.

#![deny(missing_docs)]

mod ciphertext;
mod error;
mod parameter;
mod rlwe;
mod secret_key_type;

pub mod glwe;
pub mod lwe;
pub mod plaintext;
pub mod rns_fhe;
pub mod tfhe;

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
pub(crate) use rns_fhe::*;
pub(crate) use secret_key_type::{SecretCoefficient, encode_secret_coefficient};
pub(crate) use tfhe::*;
