use primus_fhe_core::{
    CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweDecryptContext, DcrtGlweKeySwitchingContext, DcrtGlweKeySwitchingKey,
    DcrtGlweSecretKey, GlweSecretKey, HybridRnsGlweKeySwitchingContext,
    HybridRnsGlweKeySwitchingKey, HybridRnsKeySwitchDomain, RingSecretKeyType,
};
use primus_lattice::glwe::DcrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

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

    let mut rng = StdRng::seed_from_u64(0x5eed_4b53_4b);

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

    let rns_glwe_len = glwe_params.rns_glwe_len();

    // ── Two independent secret keys ─────────────────────────────
    let sk_1 = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk_1 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_1, &table);

    let sk_2 = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk_2 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_2, &table);

    // ── Key-switching key: encrypt sk_1 under sk_2 ──────────────
    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let key_switching_key =
        DcrtGlweKeySwitchingKey::generate(&sk_1, &glwe_params, &dcrt_sk_2, &domain, &mut rng);

    // ── Encrypt random plaintext under sk_1 ─────────────────────
    let input: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut ksk_context = DcrtGlweKeySwitchingContext::new(&domain, key_switching_key.input_size());
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk_1.encrypt_plaintext_inplace(&input, &mut c1, &glwe_params, &table, &mut rng);

    // Sanity: decrypt back under sk_1
    let m_dec = dcrt_sk_1.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input);

    // ── Key-switch: c1 (under sk_1) → c2 (under sk_2) ──────────
    // Requires conversion to coefficient domain first.
    let c1 = c1.into_coeff_form(&table);

    key_switching_key
        .key_switch_to(&c1, &mut c2, &domain, &mut ksk_context)
        .unwrap();

    // ── Decrypt under sk_2 ─────────────────────────────────────
    let output = dcrt_sk_2.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

    assert_eq!(input.as_ref(), output.as_ref());
}

/// Test hybrid RNS gadget GLWE key switching end-to-end:
/// encrypt under sk_1 → hybrid key-switch → decrypt under sk_2 → assert same
/// plaintext.
#[test]
fn test_rns_glwe_ksk_hybrid() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2305843009213554689;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    // Three 50-bit Q moduli + one 50-bit P modulus.
    let q_values: [ValueT; 3] = [1125899906826241, 1125899906629633, 1125899906031617];
    let p_values: [ValueT; 1] = [1125899905036289];
    let q_moduli = q_values.map(<BarrettModulus<ValueT>>::new);
    let p_moduli = p_values.map(<BarrettModulus<ValueT>>::new);

    let qp_moduli_vals: Vec<BarrettModulus<ValueT>> =
        q_moduli.iter().chain(p_moduli.iter()).copied().collect();
    let qp_table = UintDcrtTable::new(log_n, &qp_moduli_vals).unwrap();
    let q_table = UintDcrtTable::new(log_n, &q_moduli).unwrap();

    let mut rng = rand::rng();

    // ── Parameters ──────────────────────────────────────────────
    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &q_moduli,
        RingSecretKeyType::Ternary,
        3.20,
    );

    // ── Hybrid RNS parameters ───────────────────────────────────
    let decomposition_count = 2;
    let hybrid_rns = primus_rns::HybridRNS::new(&q_moduli, &p_moduli, decomposition_count).unwrap();
    let hybrid_domain = HybridRnsKeySwitchDomain::try_new(&hybrid_rns, &qp_table).unwrap();

    // ── Two independent secret keys ─────────────────────────────
    let sk_1 = GlweSecretKey::generate(&glwe_params, &mut rng);
    let sk_2 = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk_2 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_2, &q_table);

    let dcrt_sk_1 = DcrtGlweSecretKey::from_coeff_secret_key(&sk_1, &q_table);

    // ── Hybrid KSK: encrypt sk_1 under sk_2 ─────────────────────
    let key_switching_key = HybridRnsGlweKeySwitchingKey::generate(
        &sk_1,
        &glwe_params,
        &sk_2,
        &hybrid_domain,
        &mut rng,
    );

    // ── Encrypt random plaintext under sk_1 ─────────────────────
    let rns_glwe_len = glwe_params.rns_glwe_len();

    let input: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);

    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk_1.encrypt_plaintext_inplace(&input, &mut c1, &glwe_params, &q_table, &mut rng);

    // Sanity: decrypt back under sk_1
    let m_dec = dcrt_sk_1.decrypt(&c1, &glwe_params, &q_table, &mut decrypt_context);
    assert_eq!(m_dec, input);

    // ── Hybrid key-switch: c1 (under sk_1) → c2 (under sk_2) ───
    let mut hybrid_context =
        HybridRnsGlweKeySwitchingContext::new(&key_switching_key, &hybrid_domain);

    key_switching_key
        .key_switch_to(&c1, &mut c2, &hybrid_domain, &mut hybrid_context)
        .unwrap();

    // ── Decrypt under sk_2 ─────────────────────────────────────
    let output = dcrt_sk_2.decrypt(&c2, &glwe_params, &q_table, &mut decrypt_context);

    assert_eq!(
        input.as_ref(),
        output.as_ref(),
        "hybrid KSK decryption mismatch"
    );
}
