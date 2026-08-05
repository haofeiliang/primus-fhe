//! Shared plaintext encoding and secret-key metadata for homomorphic
//! encryption crates.

#![deny(missing_docs)]

mod secret_key_distr;

pub mod plaintext;

pub(crate) use plaintext::*;
pub use secret_key_distr::{SecretCoefficient, SecretKeyDistr};
