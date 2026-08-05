//! NTRU ciphertext operations.

#![deny(missing_docs)]

mod secret_key;

/// NTT-domain NTRU ciphertext.
pub type NttNtruCiphertext<T> = primus_lattice::ntru::NttNtru<T>;

pub use primus_fhe_core::SecretKeyDistr;
pub use secret_key::{NtruSecretKey, NttNtruSecretKey};
