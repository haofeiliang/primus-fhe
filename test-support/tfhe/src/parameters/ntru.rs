//! NTRU profiles separate external LWE q from accumulator Q.
//! All profiles use `PowOf2Modulus` for external q=2^24. The modulus argument
//! supplies ring Q: an NTT prime or the native torus modulus for Fourier.
//! Allowing a smaller external q does not imply FFT support for that ring modulus.

use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_lwe::LweParametersInner;
use primus_modulus::PowOf2Modulus;
use primus_reduce::RingContext;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru::{CircuitBootstrapConfig, DecompositionConfig, TfheConfig, TfheParameters};

use super::{DIMENSION, N, SPARSE_DIMENSION, SPARSE_WEIGHT};
use crate::benchmark::{LWE_STD_DEV, PbsWorkload};

/// Retains floor(value_bits/log_basis) levels; low bits can still be discarded.
fn full(log_basis: u32) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(log_basis),
        level_count: None,
    }
}

/// PBS/ManyLUT profile with independent q=2^24 and coefficient noise per key role.
/// `modulus` supplies the accumulator Q, not the external LWE modulus.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry or basis/modulus combinations.
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
    parameters(
        modulus,
        workload.lwe_dimension,
        workload.poly_length,
        secret,
        (1u64 << 24) as f64 * LWE_STD_DEV,
    )
}

/// Builds the shared NTRU key roles while varying the external LWE noise.
/// Dense and fixed-weight workloads retain different normalized input noise;
/// their BR and q-domain return-key budgets are otherwise the same.
fn parameters<T, M>(
    modulus: M,
    lwe_dimension: usize,
    poly_length: usize,
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
        external_lwe: LweParametersInner::new(
            LweDimension::new(lwe_dimension),
            PowOf2Modulus::new(q),
            secret,
            lwe_standard_deviation,
        ),
        accumulator_modulus: modulus,
        poly_length,
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

/// Shared CBS, one-hot and high-precision key profile; bind message codecs separately.
/// For NTT pass `ntt_circuit_modulus()`; Fourier uses `NativeModulus`.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry or basis/modulus combinations.
#[must_use]
pub fn circuit<T, M>(modulus: M, secret: SecretKeyDistr) -> TfheParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters(
        modulus,
        DIMENSION,
        N,
        secret,
        (1u64 << 24) as f64 * LWE_STD_DEV,
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
            log_basis: if T::BITS == 32 {
                DecompositionBaseLog::new(3)
            } else {
                DecompositionBaseLog::new(8)
            },
            level_count: Some(if T::BITS == 32 {
                DecompositionLevelCount::new(4)
            } else {
                DecompositionLevelCount::new(3)
            }),
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
/// constructor also rejects invalid geometry or basis/modulus combinations.
#[must_use]
pub fn diagnostic<T, M>(modulus: M) -> TfheParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    parameters(
        modulus,
        SPARSE_DIMENSION,
        N,
        SecretKeyDistr::fixed_hamming_weight_binary(SPARSE_DIMENSION, SPARSE_WEIGHT),
        3.2 * (1u64 << 24) as f64 / 16384.0,
    )
}
