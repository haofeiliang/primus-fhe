use std::sync::Arc;

use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweParameters, DcrtGlweAutoKey,
    DcrtGlweCiphertext, DcrtGlweDecryptContext, DcrtGlweSecretKey, GlweSecretKey,
    RingSecretKeyType,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::Polynomial;
use primus_reduce::ReduceNeg;
use rand::RngExt;

fn coefficient_automorphism(
    polynomial: &[u64],
    degree: usize,
    modulus: BarrettModulus<u64>,
) -> Vec<u64> {
    let poly_length = polynomial.len();
    let twice_poly_length = 2 * poly_length;
    let mut result = vec![0; poly_length];

    for (index, &coefficient) in polynomial.iter().enumerate() {
        let target = index * degree % twice_poly_length;
        if target < poly_length {
            result[target] = coefficient;
        } else {
            result[target - poly_length] = modulus.reduce_neg(coefficient);
        }
    }

    result
}

/// Test GLWE automorphism in the coefficient (CRT) domain.
///
/// A GLWE ciphertext is encrypted, transformed by a random odd-degree
/// automorphism k → k·α mod 2N, then decrypted. The result is checked
/// against the same automorphism applied to the secret key and ciphertext
/// in the coefficient domain.
#[test]
fn test_crt_glwe_auto() {
    type ValueT = u64;

    let dimension = 3;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    // let t: ValueT = 1 << 15;
    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = rand::rng();

    // ── Parameters ──────────────────────────────────────────────
    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );

    let moduli_count = glwe_params.cipher_moduli_count();
    let crt_poly_length = glwe_params.rns_poly_len();
    let big_uint_poly_len = glwe_params.big_uint_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    // ── Auto key: KSK for an odd-degree automorphism ────────────
    let basis = BigUintApproxSignedBasis::new(base_q, 20, None);
    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, basis);

    let mut auto_degree = rng.random_range(0..poly_length * 2);
    if auto_degree & 1 == 0 {
        auto_degree |= 1; // automorphism degree must be odd (coprime to 2N)
    }

    let auto_key = CrtGlweAutoKey::new(
        &glev_params,
        auto_degree,
        &sk,
        &dcrt_sk,
        Arc::new(table),
        &mut rng,
    );
    let table = auto_key.table();

    // ── Encrypt random plaintext ────────────────────────────────
    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::zero(rns_glwe_len);
    let mut auto_context = CrtGlweAutoContext::new(
        poly_length,
        crt_poly_length,
        big_uint_poly_len,
        moduli_count,
    );
    let mut decrypt_context = DcrtGlweDecryptContext::new(moduli_count, poly_length);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, table, &mut rng);

    // Sanity: decrypt original
    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    let c1 = c1.into_coeff_form(table);

    // ── Key-switched automorphism ───────────────────────────────
    auto_key.automorphism_to(&c1, &mut c2, &glev_params, base_q, &mut auto_context);

    let c2 = c2.into_ntt_form(table);

    let auto_msg_2 = dcrt_sk.decrypt(&c2, &glwe_params, table, &mut decrypt_context);

    let expected = coefficient_automorphism(input1.as_ref(), auto_degree, mod_t);
    assert_eq!(auto_msg_2.as_ref(), expected);
}

/// Test GLWE automorphism in the NTT (DCRT) domain.
///
/// Same as [`test_crt_glwe_auto`] but the automorphism is applied via
/// NTT-native index permutation instead of coefficient-domain permutation.
/// The ciphertext stays in the NTT domain throughout the operation.
#[test]
fn test_dcrt_glwe_auto() {
    type ValueT = u64;

    let dimension = 3;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    // let t: ValueT = 1 << 15;
    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    // let gamma: ValueT = 2199023190017;
    // let gamma: ValueT = 2305843009213554689;
    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = rand::rng();

    // ── Parameters ──────────────────────────────────────────────
    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );

    let moduli_count = glwe_params.cipher_moduli_count();
    let crt_poly_length = glwe_params.rns_poly_len();
    let big_uint_poly_len = glwe_params.big_uint_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let basis = BigUintApproxSignedBasis::new(base_q, 20, None);
    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, basis);

    let mut auto_degree = rng.random_range(0..poly_length * 2);
    if auto_degree & 1 == 0 {
        auto_degree |= 1;
    }

    let auto_key = DcrtGlweAutoKey::new(
        &glev_params,
        auto_degree,
        &dcrt_sk,
        Arc::new(table),
        &mut rng,
    );
    let table = auto_key.table();

    // ── Encrypt ─────────────────────────────────────────────────
    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut auto_context = CrtGlweAutoContext::new(
        poly_length,
        crt_poly_length,
        big_uint_poly_len,
        moduli_count,
    );
    let mut decrypt_context = DcrtGlweDecryptContext::new(moduli_count, poly_length);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── Key-switched automorphism ───────────────────────────────
    auto_key.automorphism_to(&c1, &mut c2, &glev_params, base_q, &mut auto_context);

    let auto_msg_2 = dcrt_sk.decrypt(&c2, &glwe_params, table, &mut decrypt_context);

    let expected = coefficient_automorphism(input1.as_ref(), auto_degree, mod_t);
    assert_eq!(auto_msg_2.as_ref(), expected);
}
