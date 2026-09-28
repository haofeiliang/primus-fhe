//! GLWE profiles retain the shared modulus and both PBS orders.
//! NTT uses an explicit prime; Fourier uses the native torus modulus for every
//! key role. PBS, circuit and fixed-weight profiles have distinct noise budgets.

use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use primus_tfhe_glwe::{
    CircuitBootstrapConfig, DecompositionConfig, PbsOrder, TfheConfig, TfheParameters,
};

use super::{DIMENSION, N, SPARSE_DIMENSION, SPARSE_WEIGHT, ntt_modulus};
use crate::benchmark::{GLWE_STD_DEV, LWE_STD_DEV, PbsWorkload};

fn decomposition(log_basis: u32, level_count: Option<usize>) -> DecompositionConfig {
    DecompositionConfig {
        log_basis,
        level_count,
    }
}

/// Existing dense NTT PBS profile, for Boolean and 2+2 bit workloads.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry, plaintext modulus or basis/modulus combinations.
#[must_use]
pub fn ntt_pbs<T: FheUint>(
    order: PbsOrder,
    workload: PbsWorkload,
) -> TfheParameters<T, BarrettModulus<T>> {
    let modulus = ntt_modulus();
    let (br, ks) = if T::BITS == 32 {
        ((5, 5), (2, 13))
    } else {
        ((23, 1), (3, 5))
    };
    pbs(modulus, order, workload, br, ks)
}

/// Existing dense native-torus PBS profile.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry, plaintext modulus or basis/modulus combinations.
#[must_use]
pub fn fourier_pbs<T: FheUint>(
    order: PbsOrder,
    workload: PbsWorkload,
) -> TfheParameters<T, NativeModulus<T>> {
    let (br, ks) = if T::BITS == 32 {
        ((8, 3), (2, 13))
    } else {
        ((23, 1), (3, 5))
    };
    pbs(NativeModulus::new(), order, workload, br, ks)
}

/// Builds dense PBS parameters after the caller selects backend-specific bases.
/// Each decomposition pair is (log2 radix, retained levels); normalized noise
/// is converted to coefficient units using this backend's ciphertext modulus.
fn pbs<T, M>(
    modulus: M,
    order: PbsOrder,
    workload: PbsWorkload,
    blind_rotation: (u32, usize),
    key_switching: (u32, usize),
) -> TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    super::require_word::<T>();
    let q = modulus
        .explicit_value()
        .map_or(2f64.powi(T::BITS as i32), |q| q.as_into());
    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            workload.lwe_dimension,
            T::as_from(workload.plaintext_modulus),
            modulus,
            SecretKeyDistr::UniformBinary,
            q * LWE_STD_DEV,
        ),
        accumulator_dimension: 1,
        poly_length: workload.poly_length,
        accumulator_secret_key_distr: SecretKeyDistr::UniformBinary,
        accumulator_noise_standard_deviation: (q * GLWE_STD_DEV).max(6.4),
        blind_rotation: decomposition(blind_rotation.0, Some(blind_rotation.1)),
        key_switching: decomposition(key_switching.0, Some(key_switching.1)),
        pbs_order: order,
    })
    .unwrap()
}

/// Dense CBS/ternary profile; coefficient sigma=6.4 is distinct from dense PBS.
/// For NTT pass `ntt_circuit_modulus()`; Fourier uses `NativeModulus`.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry, plaintext modulus or basis/modulus combinations.
#[must_use]
pub fn circuit<T, M>(modulus: M, order: PbsOrder, secret: SecretKeyDistr) -> TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    super::require_word::<T>();
    let q = modulus
        .explicit_value()
        .map_or(2f64.powi(T::BITS as i32), |q| q.as_into());
    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            DIMENSION,
            T::as_from(4u32),
            modulus,
            secret,
            q * LWE_STD_DEV,
        ),
        accumulator_dimension: 1,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::UniformTernary,
        accumulator_noise_standard_deviation: 6.4,
        blind_rotation: decomposition(if T::BITS == 32 { 2 } else { 8 }, None),
        key_switching: decomposition(if T::BITS == 32 { 2 } else { 8 }, None),
        pbs_order: order,
    })
    .unwrap()
}

/// CBS output scales and full-length key decompositions.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64.
#[must_use]
pub fn cbs<T: FheUint>() -> CircuitBootstrapConfig {
    super::require_word::<T>();
    let internal = decomposition(if T::BITS == 32 { 2 } else { 8 }, None);
    CircuitBootstrapConfig {
        output: decomposition(
            if T::BITS == 32 { 3 } else { 8 },
            Some(if T::BITS == 32 { 3 } else { 2 }),
        ),
        trace: internal,
        trace_noise_standard_deviation: 6.4,
        scheme_switch: internal,
        scheme_switch_noise_standard_deviation: 6.4,
    }
}

/// n=728, weight=32 profile for sparse PBS and threshold MVB.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry, plaintext modulus or basis/modulus combinations.
#[must_use]
pub fn diagnostic<T, M>(modulus: M, order: PbsOrder, plaintext_modulus: u32) -> TfheParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>,
{
    super::require_word::<T>();
    let q = modulus
        .explicit_value()
        .map_or(2f64.powi(T::BITS as i32), |q| q.as_into());
    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            SPARSE_DIMENSION,
            T::as_from(plaintext_modulus),
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(SPARSE_DIMENSION, SPARSE_WEIGHT),
            3.2 * q / 16384.0,
        ),
        accumulator_dimension: 1,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 6.4,
        blind_rotation: decomposition(if T::BITS == 32 { 2 } else { 8 }, None),
        key_switching: decomposition(if T::BITS == 32 { 2 } else { 8 }, None),
        pbs_order: order,
    })
    .unwrap()
}
