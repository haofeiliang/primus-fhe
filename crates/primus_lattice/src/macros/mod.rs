//! Ciphertext implementation macros.
//!
//! Pass type names without storage generics: `impl_common!(Lwe)`.
//! At each type declaration, group invocations in this order:
//! storage/construction, iteration/access, arithmetic, domain conversion.
//! Within arithmetic, use add/sub, negation, scalar multiply, scalar FMA,
//! then precomputed-factor multiply. Capability groups remain explicit.
//!
//! - [`common`]: constructors, byte I/O, zero initialization
//! - [`iter`]: integer ciphertext and sub-component iterators
//! - [`ops`], [`rns_ops`], [`fourier_ops`]: representation-specific arithmetic
//! - [`ntt`], [`fourier`]: representation conversions and Fourier storage

#[macro_use]
mod common;
#[macro_use]
mod iter;
#[macro_use]
mod ops;
#[macro_use]
mod rns_ops;
#[macro_use]
mod fourier_ops;
#[macro_use]
mod ntt;
#[macro_use]
mod fourier;
