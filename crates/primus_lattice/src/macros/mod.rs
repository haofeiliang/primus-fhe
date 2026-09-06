//! Ciphertext implementation macros.
//!
//! Pass type names without storage generics: `impl_common!(Lwe)`.
//! At each type declaration, group invocations in this order:
//! storage/construction, iteration/access, arithmetic, domain conversion.
//! Within arithmetic, use add/sub, negation, scalar arithmetic,
//! then precomputed-factor arithmetic and polynomial products. Capability groups remain explicit.
//!
//! - [`common`]: constructors, byte I/O, zero initialization
//! - [`iter`], [`rlwe`]: ciphertext iterators and RLWE polynomial views
//! - [`ntt_polynomial`], [`dcrt_polynomial`]: same-domain polynomial products
//! - [`ops`], [`rns_ops`], [`fourier_ops`]: representation-specific arithmetic
//! - [`ntt`], [`fourier`]: representation conversions and Fourier storage

#[macro_use]
mod common;
#[macro_use]
mod iter;
#[macro_use]
mod rlwe;
#[macro_use]
mod ops;
#[macro_use]
mod rns_ops;
#[macro_use]
mod fourier_ops;
#[macro_use]
mod ntt;
#[macro_use]
mod ntt_polynomial;
#[macro_use]
mod dcrt_polynomial;
#[macro_use]
mod fourier;
