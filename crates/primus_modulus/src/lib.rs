#![cfg_attr(feature = "simd", feature(portable_simd))]
#![deny(missing_docs)]

//! Concrete modulus types implementing the [`primus_reduce`] traits.
//!
//! | Type | Reduction | Use case |
//! |------|-----------|----------|
//! | [`NativeModulus`] | Wrapping arithmetic | Implicit modulus `2^BITS` |
//! | [`PowOf2Modulus`] | Bit masking | Representable power-of-two modulus |
//! | [`BarrettModulus`] | Barrett reduction (`m < 2^(BITS - 2)`) | Repeated multiplication and reduction |
//! | [`CompactModulus`] | Bounded arithmetic (`m < 2^(BITS - 2)`) | Basic operations without precomputation |
//! | [`UintModulus`] | Generic unsigned arithmetic | Basic operations for any representable `m > 1` |

pub use primus_integer as integer;
pub use primus_reduce as reduce;

pub mod common;

mod barrett;
mod compact;

mod native;
mod power_of_two;
mod uint;

#[cfg(feature = "derive")]
pub use primus_barrett_derive::Barrett;

pub use barrett::BarrettModulus;
pub use compact::CompactModulus;

pub use native::NativeModulus;
pub use power_of_two::PowOf2Modulus;
pub use uint::UintModulus;

#[cfg(feature = "simd")]
pub use barrett::{SimdBarrettModulus, simd_reduce_dot_product as barrett_simd_reduce_dot_product};
