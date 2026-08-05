//! Hybrid-RNS GLWE key switching from one secret key to another.

use primus_fhe_core::{
    CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptContext, DcrtGlweSecretKey,
    GlweSecretKey, HybridRnsGlweKeySwitchingContext, HybridRnsGlweKeySwitchingKey,
    HybridRnsKeySwitchDomain, RingSecretKeyType,
};
use primus_lattice::glwe::DcrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::Polynomial;
use primus_rns::HybridRNS;
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    type Value = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let plaintext_modulus = BarrettModulus::new(12289);
    let gamma = BarrettModulus::new(2305843009213554689);
    let q_moduli = [1125899906826241, 1125899906629633, 1125899906031617].map(BarrettModulus::new);
    let p_moduli = [1125899905036289].map(BarrettModulus::new);
    let qp_moduli: Vec<_> = q_moduli.iter().chain(&p_moduli).copied().collect();
    let q_table = UintDcrtTable::new(poly_length.trailing_zeros(), &q_moduli).unwrap();
    let qp_table = UintDcrtTable::new(poly_length.trailing_zeros(), &qp_moduli).unwrap();

    let glwe_parameters = CrtGlweParameters::new(
        dimension,
        poly_length,
        plaintext_modulus,
        gamma,
        &q_moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );
    let hybrid_rns = HybridRNS::new(&q_moduli, &p_moduli, 2).unwrap();
    let domain = HybridRnsKeySwitchDomain::try_new(&hybrid_rns, &qp_table).unwrap();

    let mut rng = StdRng::seed_from_u64(0x4859_4252_4944_524e);
    let input_key = GlweSecretKey::generate(&glwe_parameters, &mut rng);
    let output_key = GlweSecretKey::generate(&glwe_parameters, &mut rng);
    let input_dcrt_key = DcrtGlweSecretKey::from_coeff_secret_key(&input_key, &q_table);
    let output_dcrt_key = DcrtGlweSecretKey::from_coeff_secret_key(&output_key, &q_table);
    let switching_key = HybridRnsGlweKeySwitchingKey::generate(
        &input_key,
        &glwe_parameters,
        &output_key,
        &domain,
        &mut rng,
    );

    let plaintext: Polynomial<Vec<Value>> =
        Polynomial::random(poly_length, plaintext_modulus, &mut rng);
    let mut input: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(glwe_parameters.rns_glwe_len());
    let mut output: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(glwe_parameters.rns_glwe_len());
    input_dcrt_key.encrypt_plaintext_inplace(
        &plaintext,
        &mut input,
        &glwe_parameters,
        &q_table,
        &mut rng,
    );

    // The context owns all reusable workspace needed by online key switching.
    let mut key_switch_context = HybridRnsGlweKeySwitchingContext::new(&switching_key, &domain);
    switching_key.key_switch_to(&input, &mut output, &domain, &mut key_switch_context);

    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_parameters.size());
    let decrypted =
        output_dcrt_key.decrypt(&output, &glwe_parameters, &q_table, &mut decrypt_context);
    assert_eq!(decrypted, plaintext);
}
