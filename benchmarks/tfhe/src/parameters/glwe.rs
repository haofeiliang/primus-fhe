//! GLWE profiles retain the shared modulus and both PBS orders.
//! NTT uses an explicit prime; Fourier uses the native torus modulus for every
//! key role. PBS, circuit and fixed-weight profiles have distinct noise budgets.

use primus_glwe::GlweDimension;
use primus_glwe::SecretKeyDistr;
use primus_integer::FheUint;
use primus_lwe::LweDimension;
use primus_modulus::{BarrettModulus, NativeModulus};
use primus_reduce::RingContext;
use primus_tfhe::PolyLength;
use primus_tfhe::{DecompositionBaseLog, DecompositionLevelCount};
use primus_tfhe_glwe::{
    CbsGadgetConfig, DecompositionConfig, GadgetEncryptionConfig, PbsMessageConfig, PbsOrder,
    PbsParameters,
};

use super::{DIMENSION, N, SPARSE_DIMENSION, SPARSE_WEIGHT, ntt_modulus};
use crate::benchmark::{GLWE_STD_DEV, LWE_STD_DEV, PbsWorkload};

fn decomposition(log_basis: u32, level_count: Option<usize>) -> DecompositionConfig {
    DecompositionConfig {
        log_basis: DecompositionBaseLog::new(log_basis),
        level_count: level_count.map(DecompositionLevelCount::new),
    }
}

/// Existing dense NTT PBS profile, for Boolean and 2+2 bit workloads.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry or basis/modulus combinations.
#[must_use]
pub fn ntt_pbs<T: FheUint>(
    order: PbsOrder,
    workload: PbsWorkload,
) -> PbsParameters<T, BarrettModulus<T>> {
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
/// constructor also rejects invalid geometry or basis/modulus combinations.
#[must_use]
pub fn fourier_pbs<T: FheUint>(
    order: PbsOrder,
    workload: PbsWorkload,
) -> PbsParameters<T, NativeModulus<T>> {
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
) -> PbsParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
{
    super::require_word::<T>();
    let q = modulus
        .explicit_value()
        .map_or(2f64.powi(T::BITS as i32), |q| q.as_into());
    PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(workload.lwe_dimension),
            cipher_modulus: modulus.into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: q * LWE_STD_DEV,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(workload.poly_length),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: decomposition(blind_rotation.0, Some(blind_rotation.1)),
            noise_standard_deviation: (q * GLWE_STD_DEV).max(6.4),
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: decomposition(key_switching.0, Some(key_switching.1)),
            noise_standard_deviation: (q * GLWE_STD_DEV).max(6.4),
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        order,
        messages: PbsMessageConfig::new(T::as_from(workload.plaintext_modulus)),
    })
    .unwrap()
}

/// Dense CBS/ternary profile; coefficient sigma=6.4 is distinct from dense PBS.
/// For NTT pass `ntt_circuit_modulus()`; Fourier uses `NativeModulus`.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry or basis/modulus combinations.
#[must_use]
pub fn circuit<T, M>(modulus: M, order: PbsOrder, secret: SecretKeyDistr) -> PbsParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
{
    super::require_word::<T>();
    let q = modulus
        .explicit_value()
        .map_or(2f64.powi(T::BITS as i32), |q| q.as_into());
    let basis = decomposition(if T::BITS == 32 { 2 } else { 8 }, None);
    PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(DIMENSION),
            cipher_modulus: modulus.into(),
            secret_key_distr: secret,
            noise_standard_deviation: q * LWE_STD_DEV,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::UniformTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 6.4,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 6.4,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        order,
        messages: PbsMessageConfig::new(T::as_from(4u32)),
    })
    .unwrap()
}

/// CBS output scales and full-length key decompositions.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64.
#[must_use]
pub fn cbs<T: FheUint>() -> CbsGadgetConfig {
    super::require_word::<T>();
    let internal = decomposition(if T::BITS == 32 { 2 } else { 8 }, None);
    CbsGadgetConfig {
        output: decomposition(
            if T::BITS == 32 { 3 } else { 8 },
            Some(if T::BITS == 32 { 3 } else { 2 }),
        ),
        trace: internal,
        scheme_switch: internal,
    }
}

/// n=728, weight=32 profile for sparse PBS and threshold MVB.
///
/// # Panics
/// Panics unless the coefficient word is u32 or u64. The family parameter
/// constructor also rejects invalid geometry or basis/modulus combinations.
#[must_use]
pub fn diagnostic<T, M>(modulus: M, order: PbsOrder) -> PbsParameters<T, M>
where
    T: FheUint,
    M: RingContext<T>
        + TryFrom<primus_tfhe::ModulusConfig<M>, Error = primus_tfhe::ModulusConfigError>,
{
    super::require_word::<T>();
    let q = modulus
        .explicit_value()
        .map_or(2f64.powi(T::BITS as i32), |q| q.as_into());
    let basis = decomposition(if T::BITS == 32 { 2 } else { 8 }, None);
    PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(SPARSE_DIMENSION),
            cipher_modulus: modulus.into(),
            secret_key_distr: SecretKeyDistr::fixed_hamming_weight_binary(
                SPARSE_DIMENSION,
                SPARSE_WEIGHT,
            ),
            noise_standard_deviation: 3.2 * q / 16384.0,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 6.4,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: basis,
            noise_standard_deviation: 6.4,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        order,
        messages: PbsMessageConfig::new(T::as_from(8u32)),
    })
    .unwrap()
}
