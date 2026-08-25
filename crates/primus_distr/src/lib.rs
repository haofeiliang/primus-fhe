#![deny(missing_docs)]

//! Sampling distributions for FHE noise generation.
//!
//! This crate provides samplers for discrete probability distributions used
//! in fully homomorphic encryption (FHE) schemes:
//!
//! - **Binary** ([`BinaryDistr`]) — uniform over {0, 1}.
//! - **Sparse ternary** ([`SparseTernaryDistr`]) — {0, 1, -1} with
//!   probabilities 0.5, 0.25, 0.25.
//! - **Discrete Gaussian** ([`DiscreteGaussian`]) — centered discrete Gaussian
//!   with support on unsigned integers, wrapping negative samples modulo the
//!   modulus.
//! - **Signed discrete Gaussian** ([`SignedDiscreteGaussian`]) — centered
//!   discrete Gaussian with support on signed integers.
//!
//! # Sampler selection
//!
//! The Gaussian samplers internally choose between a CDT sampler
//! ([`CDTSampler`]) and a Ziggurat sampler ([`DiscreteZiggurat`]) based on
//! the standard deviation (threshold: σ = 20).
//! With the `high_precision` feature, portable 256-bit CDT samplers
//! ([`PreciseCDTSampler`] and [`SignedPreciseCDTSampler`]) are also
//! available.
//!
//! # Batch sampling
//!
//! Utility functions support efficient batch generation of vectors —
//! including CRT (Chinese remainder theorem) interleaved layouts where
//! values are replicated across multiple modulus slots.

mod error;
mod gaussian_core;

mod utils;

mod common;

mod binary;
mod ternary;

mod discrete_gaussian;
mod signed_discrete_gaussian;

pub mod stats;

pub use error::DistrErr;

pub use common::*;

pub use binary::BinaryDistr;
pub use ternary::SparseTernaryDistr;

#[cfg(feature = "high_precision")]
pub use discrete_gaussian::PreciseCDTSampler;
pub use discrete_gaussian::{CDTSampler, DiscreteGaussian, DiscreteZiggurat};
#[cfg(feature = "high_precision")]
pub use signed_discrete_gaussian::SignedPreciseCDTSampler;
pub use signed_discrete_gaussian::{
    SignedCDTSampler, SignedDiscreteGaussian, SignedDiscreteZiggurat,
};
