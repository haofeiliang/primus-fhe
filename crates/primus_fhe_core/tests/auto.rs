use std::sync::Arc;

use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweParameters, DcrtGlweAutoKey,
    DcrtGlweCiphertext, DcrtGlweDecryptContext, DcrtGlweSecretKey, GlweSecretKey,
    RingSecretKeyType, crt_poly_auto_inplace, dcrt_poly_ntt_auto_inplace,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::Polynomial;
use rand::RngExt;

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
    let basis = BigUintApproxSignedBasis::new(glwe_params.cipher_modulus(), 20, None, base_q);
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
    let mut auto_c1: CrtGlwe<Vec<ValueT>> = CrtGlwe::zero(rns_glwe_len);
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

    // ── Manual automorphism in coefficient domain ───────────────
    // Apply the coefficient permutation to each polynomial of the ciphertext
    // and to the secret key, producing a transformed ciphertext c1' and key sk'.
    // Decrypting c1' under dcrt_sk' should yield the same plaintext.
    let c1 = c1.into_coeff_form(table);

    c1.iter_crt_poly(crt_poly_length)
        .zip(auto_c1.iter_crt_poly_mut(crt_poly_length))
        .for_each(|(in_crt_poly, auto_crt_poly)| {
            crt_poly_auto_inplace(
                in_crt_poly.0,
                auto_crt_poly.0,
                auto_key.auto_helper(),
                poly_length,
                &moduli,
            );
        });

    let mut auto_sk_values = vec![0i64; dimension * poly_length];
    sk.iter()
        .zip(auto_sk_values.chunks_exact_mut(poly_length))
        .for_each(|(secret_poly, auto_secret_poly)| {
            primus_fhe_core::secret_poly_auto_to::<ValueT>(
                secret_poly,
                auto_secret_poly,
                auto_key.auto_helper(),
            );
        });
    let auto_sk = GlweSecretKey::new(auto_sk_values, dimension, poly_length, sk.distr());
    let dcrt_auto_sk = DcrtGlweSecretKey::from_coeff_secret_key(&auto_sk, table);

    let auto_c1 = auto_c1.into_ntt_form(table);
    let auto_msg_1 = dcrt_auto_sk.decrypt(&auto_c1, &glwe_params, table, &mut decrypt_context);

    // ── Key-switched automorphism ───────────────────────────────
    auto_key.automorphism_inplace(&c1, &mut c2, &glev_params, base_q, &mut auto_context);

    let c2 = c2.into_ntt_form(table);

    let auto_msg_2 = dcrt_sk.decrypt(&c2, &glwe_params, table, &mut decrypt_context);

    // Both approaches should agree on the transformed plaintext.
    assert_eq!(auto_msg_1.as_ref(), auto_msg_2.as_ref());
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

    let basis = BigUintApproxSignedBasis::new(glwe_params.cipher_modulus(), 20, None, base_q);
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
    let mut auto_c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
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

    // ── Manual NTT automorphism ─────────────────────────────────
    // Permute NTT indices of each polynomial in the ciphertext and secret key.
    c1.iter_dcrt_poly(crt_poly_length)
        .zip(auto_c1.iter_dcrt_poly_mut(crt_poly_length))
        .for_each(|(in_dcrt_poly, auto_dcrt_poly)| {
            dcrt_poly_ntt_auto_inplace(
                in_dcrt_poly.0,
                auto_dcrt_poly.0,
                auto_key.auto_helper(),
                poly_length,
            );
        });

    let mut dcrt_auto_sk = DcrtGlweSecretKey::zero(dimension, crt_poly_length, sk.distr());
    dcrt_sk
        .iter_dcrt_poly()
        .zip(dcrt_auto_sk.iter_dcrt_poly_mut())
        .for_each(|(in_dcrt_poly, auto_dcrt_poly)| {
            dcrt_poly_ntt_auto_inplace(
                in_dcrt_poly.0,
                auto_dcrt_poly.0,
                auto_key.auto_helper(),
                poly_length,
            );
        });

    let auto_msg_1 = dcrt_auto_sk.decrypt(&auto_c1, &glwe_params, table, &mut decrypt_context);

    // ── Key-switched automorphism ───────────────────────────────
    auto_key.automorphism_inplace(&c1, &mut c2, &glev_params, base_q, &mut auto_context);

    let auto_msg_2 = dcrt_sk.decrypt(&c2, &glwe_params, table, &mut decrypt_context);

    assert_eq!(auto_msg_1.as_ref(), auto_msg_2.as_ref());
}
