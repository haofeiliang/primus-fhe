#![deny(missing_docs)]

//! Ciphertext storage and low-level lattice arithmetic.
//!
//! # Correctness
//!
//! Ciphertext wrappers own or borrow raw storage. They do not carry a secret key,
//! polynomial size, modulus, gadget basis, or transform table, and their raw
//! constructors do not validate these properties. The caller must establish the
//! layout and mathematical contracts below before invoking an operation.
//!
//! - Buffers must contain complete ciphertexts in the documented representation.
//!   Lengths include every component, gadget level, row, and RNS modulus block.
//!   Size descriptors validate dimension arithmetic, not the buffers they describe.
//! - Arithmetic operands must have compatible keys, encodings, moduli, and layouts.
//!   Gadget operands must also agree on basis and level/row order. NTT operands
//!   must use the same transform convention and evaluation order.
//! - Values must satisfy the selected arithmetic backend's input ranges. Unless
//!   an operation explicitly permits lazy values, supply canonical residues; for
//!   the native modulus every value of the underlying unsigned type is canonical.
//! - Fourier ciphertexts use normalized torus transforms. Table, packing, and
//!   scale must agree; floating-point transforms and gadget decomposition can
//!   introduce approximation error. Noise bounds and decryptability belong to
//!   the higher-level cryptographic API.
//! - Output storage and reusable contexts must have the exact shapes required by
//!   each operation. An overwriting operation initializes its output; an
//!   accumulating operation requires a valid initialized accumulator.
//!
//! # Panics
//!
//! This crate does not systematically check these correctness contracts. Debug
//! assertions diagnose selected violations but are not release-mode validation.
//! Slice operations and arithmetic backends may panic on malformed inputs;
//! iterator-based operations may instead omit trailing blocks or process only a
//! common prefix. Absence of a panic does not establish a valid ciphertext.
//! Method-level panic documentation identifies specific failure conditions,
//! rather than promising rejection of every invalid input.
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

mod gadget;
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
