//! Plaintext encoding/decoding strategies for LWE/RLWE/GLWE.
//!
//! The [`PlaintextCodec`] is the recommended API for parameter-level usage.

mod rns;
mod single_modulus;

pub use rns::RnsCoeffCodec;
pub use single_modulus::PlaintextCodec;

/// Plaintext embedding used when lifting residues from `Z_t` into the ciphertext modulus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlaintextEmbedding {
    /// Lifts messages as unsigned residues in `[0, t)`.
    Unsigned,
    /// Lifts messages into the centered interval `[-t/2, t/2)`.
    Centered,
}
