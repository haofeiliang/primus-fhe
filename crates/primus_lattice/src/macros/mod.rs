//! Macro library for `primus_lattice`.
//!
//! Organized by category:
//! - [`common`]  – constructors, byte conversion, zero-init
//! - [`iter`]    – chunked iterators and sub-component iteration
//! - [`ops`]     – element-wise arithmetic
//! - [`ntt`]     – NTT / CRT ↔ DCRT domain transforms
//! - [`fourier`] – Fourier-domain iterators, core methods, and FFT conversions

#[macro_use]
mod common;
#[macro_use]
mod iter;
#[macro_use]
mod ops;
#[macro_use]
mod ntt;
#[macro_use]
mod fourier;
