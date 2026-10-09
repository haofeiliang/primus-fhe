//! NTRU profiles separate external LWE q from accumulator Q.
//! All profiles use `PowOf2Modulus` for external q=2^24. The modulus argument
//! supplies ring Q: an NTT prime or the native torus modulus for Fourier.
//! Allowing a smaller external q does not imply FFT support for that ring modulus.

use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_modulus::PowOf2Modulus;
use primus_reduce::RingContext;
use primus_tfhe::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru::{
    CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, PbsMessageConfig, PbsParameters,
};

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
) -> PbsParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
{
    parameters(
        modulus,
        workload.lwe_dimension,
        workload.poly_length,
        secret,
        (1u64 << 24) as f64 * LWE_STD_DEV,
        PbsMessageConfig::new(T::as_from(workload.plaintext_modulus)),
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
    messages: PbsMessageConfig<T>,
) -> PbsParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
{
    super::require_word::<T>();
    // Ring noise remains 0.7: CBS multiplies errors by f/f². Fresh LWE and
    // return KS retain independent coefficient-unit budgets at q=2^24.
    PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
        external_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(lwe_dimension),
            cipher_modulus: primus_tfhe::ModulusConfig::Explicit(T::ONE << 24u32),
            secret_key_distr: secret,
            noise_standard_deviation: lwe_standard_deviation,
        },
        acc_modulus: modulus.into(),
        bsk_poly_length: PolyLength::new(poly_length),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: full(if T::BITS == 32 { 2 } else { 8 }),
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: full(3),
            noise_standard_deviation: 3.2,
        },
        algorithm: primus_tfhe::BlindRotationMethod::Classic,
        messages,
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
pub fn circuit<T, M>(modulus: M, secret: SecretKeyDistr) -> PbsParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
{
    parameters(
        modulus,
        DIMENSION,
        N,
        secret,
        (1u64 << 24) as f64 * LWE_STD_DEV,
        PbsMessageConfig::new(T::as_from(4u32)),
    )
}

/// Circuit output, trace and scheme-switch bases; key rows inherit ring noise.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64.
#[must_use]
pub fn cbs<T: FheUint>() -> CbsGadgetConfig {
    super::require_word::<T>();
    let internal = full(if T::BITS == 32 { 2 } else { 8 });
    CbsGadgetConfig {
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
        scheme_switch: internal,
    }
}

/// Fixed-weight profile for paired classic/sparse PBS, CBS, one-hot and MVB.
/// CBS/one-hot consumers select the circuit modulus and attach their CBS bases.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry or basis/modulus combinations.
#[must_use]
pub fn diagnostic<T, M>(modulus: M) -> PbsParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
{
    parameters(
        modulus,
        SPARSE_DIMENSION,
        N,
        SecretKeyDistr::fixed_hamming_weight_binary(SPARSE_DIMENSION, SPARSE_WEIGHT),
        3.2 * (1u64 << 24) as f64 / 16384.0,
        PbsMessageConfig::new(T::as_from(8u32)),
    )
}
