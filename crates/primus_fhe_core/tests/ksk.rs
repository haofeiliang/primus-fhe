use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweKeySwitchingContext, CrtGlweKeySwitchingKey, CrtGlweParameters,
    CrtGlweSecretKey, DcrtGlweCiphertext, DcrtGlweDecryptContext, DcrtGlweSecretKey,
    RingSecretKeyType,
};
use primus_lattice::glwe::DcrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::Polynomial;

/// Test RNS-based GLWE key switching end-to-end:
/// encrypt under sk_1 → key-switch → decrypt under sk_2 → assert same plaintext.
#[test]
fn test_rns_glwe_ksk() {
    type ValueT = u64;

    let dimension = 3;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2305843009213554689;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    // Two 50-bit RNS moduli: Q = q₀ · q₁
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
    let big_uint_poly_len = glwe_params.big_uint_poly_len();
    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    // ── Two independent secret keys ─────────────────────────────
    let sk_1 = CrtGlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk_1 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_1, &table);

    let sk_2 = CrtGlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk_2 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_2, &table);

    // ── Key-switching key: encrypt sk_1 under sk_2 ──────────────
    let basis = BigUintApproxSignedBasis::new(glwe_params.cipher_modulus(), 20, None, base_q);
    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, basis);

    let key_switching_key = CrtGlweKeySwitchingKey::new(
        &sk_1,
        &glwe_params,
        &dcrt_sk_2,
        &glev_params,
        &table,
        &mut rng,
    );

    // ── Encrypt random plaintext under sk_1 ─────────────────────
    let input: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut ksk_context =
        CrtGlweKeySwitchingContext::new(poly_length, rns_poly_len, big_uint_poly_len, moduli_count);
    let mut decrypt_context = DcrtGlweDecryptContext::new(moduli_count, poly_length);

    dcrt_sk_1.encrypt_plaintext_inplace(&input, &mut c1, &glwe_params, &table, &mut rng);

    // Sanity: decrypt back under sk_1
    let m_dec = dcrt_sk_1.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input);

    // ── Key-switch: c1 (under sk_1) → c2 (under sk_2) ──────────
    // Requires conversion to coefficient domain first.
    let c1 = c1.into_coeff_form(&table);

    key_switching_key.key_swithching_inplace(
        &c1,
        &mut c2,
        glev_params.basis(),
        &table,
        base_q,
        &mut ksk_context,
    );

    // ── Decrypt under sk_2 ─────────────────────────────────────
    let output = dcrt_sk_2.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

    assert_eq!(input.as_ref(), output.as_ref());
}
