//! Historical PBS/Boolean cost fixture (n=512), not a security parameter recommendation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_tfhe_glwe::PbsOrder;

use primus_tfhe_glwe_ntt::TfheParameters;

pub fn parameters_with_order(order: PbsOrder) -> TfheParameters<u32> {
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
        SecretKeyDistr::UniformBinary,
        3.2 * (CIPHERTEXT_MODULUS as f64 / 2.0f64.powi(14)),
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::SparseTernary,
        6.4,
    );
    let bootstrapping = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 7, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(CIPHERTEXT_MODULUS), 2, Some(13)),
        order,
    )
    .unwrap()
}
