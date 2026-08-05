//! Single-modulus LWE parameters, keys, encryption and key switching.

#![deny(missing_docs)]

mod key_switch;
mod parameter;
mod secret_key;

/// Owned single-message LWE ciphertext.
pub type LweCiphertext<T> = primus_lattice::lwe::Lwe<Vec<T>>;

/// Owned packed multi-message LWE ciphertext.
pub type MultiMsgLweCiphertext<T> = primus_lattice::lwe::MultiMsgLwe<Vec<T>>;

pub use key_switch::LweKeySwitchingKey;
pub use parameter::{LweKeySwitchingParameters, LweParameters};
pub use primus_fhe_core::{SecretCoefficient, SecretKeyDistr};
pub use secret_key::LweSecretKey;

use primus_fhe_core::plaintext::{PlaintextCodec, PlaintextEmbedding};
