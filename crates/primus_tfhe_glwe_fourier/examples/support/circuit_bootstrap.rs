//! Shared arithmetic profile for the CBS example and cost benchmark.
//! These parameters have no production security or failure-rate assessment.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::FftTable;
use primus_glwe::{GlevParameters, GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{CircuitBootstrapParameters, PbsOrder, TfheContext, TfheParameters};

pub const N: usize = 1024;
pub const DIMENSION: usize = 728;
pub const SEED: u64 = 0x4231_3300;

pub fn context<Table: FftTable>(order: PbsOrder) -> TfheContext<u64, Table> {
    let modulus = NativeModulus::new();
    let parameters = TfheParameters::try_new(
        LweParameters::new(
            DIMENSION,
            4,
            modulus,
            SecretKeyDistr::UniformBinary,
            3.2 * 2f64.powi(64) / 16384.0,
        ),
        GlweParameters::new(1, N, 4, modulus, SecretKeyDistr::UniformTernary, 6.4),
        ApproxSignedBasis::new(None, 8, Some(6)),
        ApproxSignedBasis::new(None, 8, Some(6)),
        order,
    )
    .unwrap();
    TfheContext::try_new(parameters, Table::new(N.trailing_zeros()).unwrap()).unwrap()
}

pub fn parameters(tfhe: &TfheParameters<u64>) -> CircuitBootstrapParameters<u64> {
    CircuitBootstrapParameters::try_new(
        tfhe,
        ApproxSignedBasis::new(None, 8, Some(3)),
        GlevParameters::with_glwe_params(tfhe.accumulator_glwe(), 8, Some(7)),
        GlevParameters::with_glwe_params(tfhe.accumulator_glwe(), 10, Some(5)),
    )
    .unwrap()
}
