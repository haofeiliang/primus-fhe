//! NTRU profiles separate external LWE q from accumulator Q.
//! All profiles use `PowOf2Modulus` for external q=2^24. The modulus argument
//! supplies ring Q: an NTT prime or the native torus modulus for Fourier.
//! Allowing a smaller external q does not imply FFT support for that ring modulus.

use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_modulus::PowOf2Modulus;
use primus_reduce::RingContext;
use primus_tfhe_ntru::{CircuitBootstrapConfig, DecompositionConfig, TfheConfig, TfheParameters};

use super::{DIMENSION, N, SPARSE_DIMENSION, SPARSE_WEIGHT};
use crate::benchmark::{LWE_STD_DEV, PbsWorkload};

/// Retains floor(value_bits/log_basis) levels; low bits can still be discarded.
fn full(log_basis: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis,
        level_count: None,
    }
}

/// PBS/ManyLUT profile with independent q=2^24 and coefficient noise per key role.
/// `modulus` supplies the accumulator Q, not the external LWE modulus.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry, plaintext modulus or basis/modulus combinations.
#[must_use]
pub fn pbs<T, M>(
    modulus: M,
    workload: PbsWorkload,
    secret: SecretKeyDistr,
) -> TfheParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters(modulus, workload, secret, (1u64 << 24) as f64 * LWE_STD_DEV)
}

/// Builds the shared NTRU key roles while varying the external LWE noise.
/// Dense and fixed-weight workloads retain different normalized input noise;
/// their BR and q-domain return-key budgets are otherwise the same.
fn parameters<T, M>(
    modulus: M,
    workload: PbsWorkload,
    secret: SecretKeyDistr,
    lwe_standard_deviation: f64,
) -> TfheParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    super::require_word::<T>();
    let q = T::ONE << 24u32;
    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            workload.lwe_dimension,
            T::as_from(workload.plaintext_modulus),
            PowOf2Modulus::new(q),
            secret,
            lwe_standard_deviation,
        ),
        accumulator_modulus: modulus,
        poly_length: workload.poly_length,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        // Preserve the existing NTRU ring noise: CBS multiplies errors by f/f².
        // External LWE and return KS use their independent q-domain budgets.
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: full(if T::BITS == 32 { 2 } else { 8 }),
        key_switching: full(3),
        key_switching_noise_standard_deviation: 3.2,
    })
    .unwrap()
}

/// CBS and one-hot profile; t=8 also supports high-precision lookup.
/// For NTT pass `ntt_circuit_modulus()`; Fourier uses `NativeModulus`.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry, plaintext modulus or basis/modulus combinations.
#[must_use]
pub fn circuit<T, M>(
    modulus: M,
    plaintext_modulus: u32,
    secret: SecretKeyDistr,
) -> TfheParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    pbs(
        modulus,
        PbsWorkload {
            name: "circuit",
            lwe_dimension: DIMENSION,
            poly_length: N,
            plaintext_modulus,
        },
        secret,
    )
}

/// Circuit output basis and independent trace/scheme-switch key noise.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64.
#[must_use]
pub fn cbs<T: FheUint>() -> CircuitBootstrapConfig {
    super::require_word::<T>();
    let internal = full(if T::BITS == 32 { 2 } else { 8 });
    CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: if T::BITS == 32 { 3 } else { 8 },
            level_count: Some(if T::BITS == 32 { 4 } else { 3 }),
        },
        trace: internal,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 0.7,
    }
}

/// Fixed-weight profile for sparse PBS and MVB's narrow input cells.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry, plaintext modulus or basis/modulus combinations.
#[must_use]
pub fn diagnostic<T, M>(
    modulus: M,
    plaintext_modulus: u32,
) -> TfheParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters(
        modulus,
        PbsWorkload {
            name: "fixed_weight",
            lwe_dimension: SPARSE_DIMENSION,
            poly_length: N,
            plaintext_modulus,
        },
        SecretKeyDistr::fixed_hamming_weight_binary(SPARSE_DIMENSION, SPARSE_WEIGHT),
        3.2 * (1u64 << 24) as f64 / 16384.0,
    )
}
