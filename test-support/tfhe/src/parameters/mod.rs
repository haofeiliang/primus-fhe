//! Explicit arithmetic profiles for representative TFHE workloads.
//!
//! These are functional/performance fixtures, not assessed security parameters.
//! Ordinary tests should keep their small geometries. The opt-in
//! `validate_parameters` example checks these larger profiles; the parameter
//! guide records noise units, decomposition and measured margins.

use primus_integer::FheUint;
use primus_modulus::BarrettModulus;

pub mod glwe;
pub mod ntru;

/// Fixed seeds chosen before profile validation; never search for passing seeds.
pub const VALIDATION_SEEDS: [u64; 2] = [42, 4242];
/// Ring length of circuit, sparse and threshold profiles.
pub const N: usize = 1024;
/// Small/external LWE dimension for dense profiles.
pub const DIMENSION: usize = 800;
/// Existing fixed-weight diagnostic geometry, also used by sparse PBS.
pub const SPARSE_DIMENSION: usize = 728;
/// Exact nonzero count of the diagnostic binary LWE secret.
pub const SPARSE_WEIGHT: usize = 32;

// The arithmetic trait also supports u16; these fixtures deliberately do not.
fn require_word<T: FheUint>() {
    assert!(
        matches!(T::BITS, 32 | 64),
        "TFHE profiles require u32 or u64"
    );
}

/// Explicit NTT modulus selected by word width, with roots for N=1024/2048.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64.
#[must_use]
pub fn ntt_modulus<T: FheUint>() -> BarrettModulus<T> {
    require_word::<T>();
    use crate::benchmark::{NTT_Q32, NTT_Q64};
    BarrettModulus::new(if T::BITS == 32 {
        T::as_from(NTT_Q32)
    } else {
        T::as_from(NTT_Q64)
    })
}

/// Wider u32 NTT modulus for circuit products; the u64 modulus is unchanged.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64.
#[must_use]
pub fn ntt_circuit_modulus<T: FheUint>() -> BarrettModulus<T> {
    require_word::<T>();
    if T::BITS == 32 {
        BarrettModulus::new(T::as_from(998_244_353u32))
    } else {
        ntt_modulus()
    }
}
