#![deny(missing_docs)]

//! Defines some lattice cryptographic structure.
//!
//! # Features
//!
//! - `rns` (disabled by default) enables CRT/DCRT ciphertexts, their multiplication
//!   workspace, and the CRT conversions on [`glwe::BigUintGlwe`].
//! - `simd` enables nightly SIMD support in the arithmetic dependencies. It does
//!   not enable `rns`; when both are enabled, the RNS dependency also uses SIMD.
//!
//! [`glwe::BigUintGlwe`], [`RnsGlweSize`], and [`RnsGadgetSize`] remain available
//! without `rns`: their storage and layout APIs do not depend on RNS arithmetic.

#[macro_use]
mod macros;

mod size;

pub use size::{
    GadgetSize, GlweSize, GlweSizeError, MAX_POLY_LENGTH, MIN_POLY_LENGTH, RnsGadgetSize,
    RnsGlweSize,
};

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
/// GSW-style NTRU ciphertexts.
pub mod ngsw;
/// Gadget-decomposed NTRU ciphertexts.
pub mod nlev;
/// NTRU ciphertexts.
pub mod ntru;
/// RGSW matrix ciphertexts (ring variant).
pub mod rgsw;
/// RLev gadget-decomposed ciphertexts (ring variant).
pub mod rlev;
/// Ring-LWE (RLWE) ciphertexts.
pub mod rlwe;
