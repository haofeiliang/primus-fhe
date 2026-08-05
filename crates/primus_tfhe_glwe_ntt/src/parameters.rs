//! Parameter types and built-in parameter sets for the NTT backend.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    SecretKeyDistr,
    glwe::{GgswParameters, GlweParameters},
    lwe::LweParameters,
};
use primus_modulus::BarrettModulus;
use primus_tfhe::PbsOrder;

/// GLWE-TFHE parameters for the explicit-modulus NTT backend.
pub type TfheParameters<T> = primus_tfhe::TfheParameters<T, BarrettModulus<T>, BarrettModulus<T>>;

/// Returns the temporary Boolean parameter set used by tests and benchmarks.
///
/// # Warning
///
/// These parameters have not been validated for a target security level or
/// failure probability. They are intended only for development, testing, and
/// benchmarking, and must not be used in production.
pub fn boolean_parameters()
-> primus_tfhe::TfheParameters<u32, BarrettModulus<u32>, BarrettModulus<u32>> {
    const LWE_DIMENSION: usize = 512;
    const GLWE_DIMENSION: usize = 1;
    const POLY_LENGTH: usize = 1024;
    const PLAINTEXT_MODULUS: u32 = 4;
    const CIPHERTEXT_MODULUS: u32 = 132_120_577;

    let modulus = BarrettModulus::new(CIPHERTEXT_MODULUS);
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::Binary,
        3.2 * (CIPHERTEXT_MODULUS as f64 / 2.0f64.powi(14)),
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::Ternary,
        6.4,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 7, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(CIPHERTEXT_MODULUS), 2, Some(13)),
        PbsOrder::BootstrapKeyswitch,
    )
    .unwrap()
}
