//! NTRU profiles separate external LWE q from accumulator Q.
//! All profiles use `PowOf2Modulus` for external q=2^24. The modulus argument
//! supplies ring Q: an NTT prime or the native torus modulus for Fourier.
//! Allowing a smaller external q does not imply FFT support for that ring modulus.

use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::PowOf2Modulus;
use primus_reduce::RingContext;
use primus_tfhe::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_ntru::{
    CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, PbsParameters,
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
) -> PbsParameters<T, M, PowOf2Modulus<T>>
where
    T: FheUint,
    M: RingContext<T>,
{
    super::require_word::<T>();
    let q = T::ONE << 24u32;
    let external_lwe = LweEncryptionParameters::new(
        LweDimension::new(lwe_dimension),
        PowOf2Modulus::new(q),
        secret,
        lwe_standard_deviation,
    );
    // Preserve the NTRU ring noise: CBS multiplies errors by f/f².
    // Fresh LWE and return KS retain independent q-domain budgets.
    let bsk_gadget = GadgetEncryptionConfig {
        decomposition: full(if T::BITS == 32 { 2 } else { 8 }),
        noise_standard_deviation: 0.7,
    };
    let blind_rotation = primus_ntru::NlevParameters::try_from_parts(
        std::sync::Arc::new(primus_ntru::NtruEncryptionParameters::new(
            PolyLength::new(poly_length),
            modulus,
            SecretKeyDistr::SparseTernary,
            bsk_gadget.noise_standard_deviation,
        )),
        bsk_gadget
            .decomposition
            .try_build(modulus.explicit_value())
            .unwrap(),
    )
    .unwrap();
    PbsParameters::try_new(
        external_lwe,
        blind_rotation,
        GadgetEncryptionConfig {
            decomposition: full(3),
            noise_standard_deviation: 3.2,
        },
    )
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
