//! AVX2-accelerated forward and inverse NTT transforms for u32.
//!
//! All stages are vectorized using 256-bit vectors (8 × u32 lanes):
//! - T8 (t ≥ 8): broadcast W, contiguous x/y loads.
//! - T4 (t = 4): `permute2x128` deinterleave.
//! - T2 (t = 2): `unpacklo/hi_epi64` + `permute4x64` deinterleave.
//! - T1 (t = 1): `permutevar8x32` gather-like deinterleave.
//!
//! Requires `n ≥ 32` — polynomial lengths below that are handled by
//! the scalar backend directly.
//!
//! # Safety
//!
//! The table dispatcher calls the unsafe transform entry points only after
//! checking [`crate::constants::HAS_AVX2`]. Helpers inherit that target feature;
//! their local unsafe blocks are limited to unchecked slicing and vector loads.

mod arithmetic;
mod butterfly;
mod permute;
pub(in crate::ntt::prime32) mod precompute;
mod transform;
