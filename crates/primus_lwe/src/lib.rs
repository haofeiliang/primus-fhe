//! Single-modulus LWE parameters, keys, encryption and key switching.
//!
//! [`LweSecretKey`] encodes messages using [`LweParameters`]. Its `encrypt_to`
//! methods reuse caller-owned ciphertext storage, and decryption accepts both
//! owned and borrowed [`primus_lattice::lwe::Lwe`] values.
//!
//! [`LweSecretKeyRef`] borrows encoded or signed coefficients for raw operations:
//! `encrypt_encoded` encrypts an already scaled residue (zero gives a randomized
//! encryption of zero), and `decrypt_phase` returns `b - <a,s>` without decoding.
//! These operations take the modulus and samplers directly, so ring-key callers
//! can reuse their own noise parameters without constructing LWE parameters.
//!
//! [`LwePublicKey`] implements Lindner–Peikert-style public-key encryption with
//! a square matrix and sparse ternary ephemeral secrets. It produces the same
//! ciphertext layout, so secret-key decryption and key switching also accept
//! public-key ciphertexts. Its noise budget differs from secret-key encryption;
//! see the public key's correctness contract before choosing parameters.
//!
//! Both keys provide `encrypt_batch` / `encrypt_batch_to` for independent
//! samples in a contiguous `Vec<T>`. Explicit embedding variants also support
//! centered messages. Batch output methods accept `&mut [T]`, and decryption
//! accepts `&[T]`. Every chunk contains `dimension + 1` coefficients, including
//! its body. Use [`primus_lattice::lwe::LweIter`] / `LweIterMut` to borrow samples.
//! Secret-key batch operations, including raw `encrypt_encoded_batch` and
//! `decrypt_phase_batch`, require [`LweSecretKey`] with encoded coefficients.
//! [`LweSecretKeyRef`] supports single-ciphertext raw operations only; signed
//! callers must encode and store a reusable key before batching.
//! Batch operations validate the complete length before iteration.
//! Empty batches consume no randomness. Batch sampling order need not match
//! repeated single-message calls; public-key batching reuses rows across a small
//! output tile. The separate packed multi-message methods retain their shared-mask layout.
//!
//! [`LweKeySwitchingKey::key_switch_batch_to`] uses the same contiguous layout,
//! with separate input/output dimensions. It reuses each key entry across a small
//! tile, needs no heap scratch, and produces exactly the same coefficients as
//! repeated single-ciphertext key switching.
//!
//! | Input / result | Single ciphertext | Independent batch |
//! |---|---|---|
//! | Message, unsigned embedding | `encrypt` / `encrypt_to` | `encrypt_batch` / `encrypt_batch_to` |
//! | Message, selected embedding | `encrypt_with_embedding` / `encrypt_with_embedding_to` | `encrypt_batch_with_embedding` / `encrypt_batch_with_embedding_to` |
//! | Encoded residue | `encrypt_encoded` / `encrypt_encoded_to` | `encrypt_encoded_batch` / `encrypt_encoded_batch_to` |
//! | Decoded message | `decrypt` | `decrypt_batch` / `decrypt_batch_to` |
//! | Noisy phase | `decrypt_phase` | `decrypt_phase_batch` / `decrypt_phase_batch_to` |
//!
//! Select centered encryption with [`primus_encoding::PlaintextEmbedding::Centered`].
//! [`LweSecretKey::decrypt_with_noise`] also takes an explicit embedding to
//! measure circular distance from the decoded message's encoding.

#![deny(missing_docs)]

mod batch;
mod key_switch;
mod parameter;
mod public_key;
mod secret_key;

/// Owned single-message LWE ciphertext.
pub type LweCiphertext<T> = primus_lattice::lwe::Lwe<Vec<T>>;

/// Owned packed multi-message LWE ciphertext.
pub type MultiMsgLweCiphertext<T> = primus_lattice::lwe::MultiMsgLwe<Vec<T>>;

pub use key_switch::LweKeySwitchingKey;
pub use parameter::{LweParameterError, LweParameters};
pub use primus_distr::SecretKeyDistr;
pub use public_key::LwePublicKey;
pub use secret_key::{LweSecretKey, LweSecretKeyRef};

use primus_encoding::{PlaintextEmbedding, RoundedCodec};
