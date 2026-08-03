#![deny(missing_docs)]

//! Defines some lattice cryptographic structure.

#[macro_use]
mod macros;

/// Context types and scratch buffers.
pub mod context;
/// GGSW matrix ciphertexts.
pub mod ggsw;
/// GLev gadget-decomposed ciphertexts.
pub mod glev;
/// Module-LWE (GLWE) ciphertexts: [`coeff`](crate::glwe::Glwe), [`ntt`](crate::glwe::NttGlwe), [`fourier`](crate::glwe::FourierGlwe).
pub mod glwe;
/// Standard LWE ciphertexts.
pub mod lwe;
/// NTRU ciphertexts.
pub mod ntru;
/// RGSW matrix ciphertexts (ring variant).
pub mod rgsw;
/// RLev gadget-decomposed ciphertexts (ring variant).
pub mod rlev;
/// Ring-LWE (RLWE) ciphertexts.
pub mod rlwe;
