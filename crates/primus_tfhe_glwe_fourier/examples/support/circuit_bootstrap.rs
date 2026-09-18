//! Shared arithmetic profile for the CBS example and cost benchmark.
//! These parameters have no production security or failure-rate assessment.

use primus_fft::FftTable;
use primus_glwe::SecretKeyDistr;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapParameters, DecompositionConfig, PbsOrder, TfheConfig,
    TfheContext, TfheParameters,
};

pub const N: usize = 1024;
pub const DIMENSION: usize = 728;
pub const SEED: u64 = 0x4231_3300;

pub fn context<Table: FftTable>(order: PbsOrder) -> TfheContext<u64, Table> {
    let modulus = NativeModulus::new();
    let parameters = TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            DIMENSION,
            4,
            modulus,
            SecretKeyDistr::UniformBinary,
            3.2 * 2f64.powi(64) / 16384.0,
        ),
        accumulator_dimension: 1,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::UniformTernary,
        accumulator_noise_standard_deviation: 6.4,
        blind_rotation: DecompositionConfig {
            log_basis: 8,
            level_count: Some(6),
        },
        key_switching: DecompositionConfig {
            log_basis: 8,
            level_count: Some(6),
        },
        pbs_order: order,
    })
    .unwrap();
    TfheContext::try_from_parameters(parameters).unwrap()
}

pub fn parameters(tfhe: &TfheParameters<u64>) -> CircuitBootstrapParameters<u64> {
    CircuitBootstrapParameters::try_from_config(
        tfhe,
        CircuitBootstrapConfig {
            output: DecompositionConfig {
                log_basis: 8,
                level_count: Some(3),
            },
            trace: DecompositionConfig {
                log_basis: 8,
                level_count: Some(7),
            },
            trace_noise_standard_deviation: 6.4,
            scheme_switch: DecompositionConfig {
                log_basis: 10,
                level_count: Some(5),
            },
            scheme_switch_noise_standard_deviation: 6.4,
        },
    )
    .unwrap()
}
