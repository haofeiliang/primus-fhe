use primus_fhe_core::{
    CrtGlevParameters, CrtGlweExpandCoeffContext, CrtGlweExpandCoeffKey,
    CrtGlweExpandCoeffSyncPool, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweDecryptContext, DcrtGlweExpandCoeffContext, DcrtGlweExpandCoeffKey,
    DcrtGlweExpandCoeffSyncPool, DcrtGlweSecretKey, GlweSecretKey, RingSecretKeyType,
};
use primus_lattice::glwe::CrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::Polynomial;

/// Test coefficient expansion in the coefficient (CRT) domain.
///
/// Expands a GLWE ciphertext encrypting m(X) into N ciphertexts,
/// one per coefficient: the i-th output encrypts m_i (the i-th coefficient).
/// Verifies full expansion (all N coefficients) and partial expansion (first 256).
#[test]
fn test_crt_glwe_expand_coefficients() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

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

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    // ── Expansion key (CRT domain) ──────────────────────────────
    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let expand_key = CrtGlweExpandCoeffKey::new(&domain, &sk, &dcrt_sk, &mut rng);

    // ── Encrypt ─────────────────────────────────────────────────
    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<CrtGlwe<Vec<ValueT>>> = vec![CrtGlwe::zero(rns_glwe_len); poly_length];
    let mut expand_context = CrtGlweExpandCoeffContext::new(&domain);
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    // Sanity
    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── Full coefficient expansion ──────────────────────────────
    // Requires conversion to coefficient domain first.
    let c1 = c1.into_coeff_form(&table);

    expand_key.expand_coefficients_inplace(&c1, &mut c_expand, &domain, &mut expand_context);

    // Each output decrypts to (m_i, 0, …, 0)
    for (cipher, &input) in c_expand.into_iter().zip(input1.iter()) {
        let cipher = cipher.into_ntt_form(&table);
        let m_dec = dcrt_sk.decrypt(&cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // ── Partial coefficient expansion (first 256) ───────────────
    // Wraps back to DCRT domain, zeros out high coefficients, re-encrypts.
    let mut c1 = DcrtGlweCiphertext::new(c1.0);

    input1[256..].fill(0);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let c1 = c1.into_coeff_form(&table);

    let mut c_expand: Vec<CrtGlwe<Vec<ValueT>>> = vec![CrtGlwe::zero(rns_glwe_len); 256];

    expand_key.expand_partial_coefficients_inplace(
        &c1,
        &mut c_expand,
        &domain,
        &mut expand_context,
    );

    for (cipher, &input) in c_expand.into_iter().zip(input1.iter()) {
        let cipher = cipher.into_ntt_form(&table);
        let m_dec = dcrt_sk.decrypt(&cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }
}

/// Test coefficient expansion in the NTT (DCRT) domain.
///
/// Same as [`test_crt_glwe_expand_coefficients`] but the ciphertext stays
/// in the NTT domain — no conversion to coefficient form required.
#[test]
fn test_dcrt_glwe_expand_coefficients() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

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

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    // ── Expansion key (DCRT domain) ─────────────────────────────
    let expand_key = DcrtGlweExpandCoeffKey::new(&domain, &dcrt_sk, &mut rng);

    // ── Encrypt ─────────────────────────────────────────────────
    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<DcrtGlweCiphertext<Vec<ValueT>>> =
        vec![DcrtGlweCiphertext::zero(rns_glwe_len); poly_length];
    let mut expand_context = DcrtGlweExpandCoeffContext::new(&domain);
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── Full expansion (input stays in NTT domain) ──────────────
    expand_key.expand_coefficients_inplace(&c1, &mut c_expand, &domain, &mut expand_context);

    // Results are already in NTT domain — decrypt directly.
    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        let m_dec = dcrt_sk.decrypt(cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // ── Partial expansion (first 256) ───────────────────────────
    input1[256..].fill(0);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let mut c_expand: Vec<DcrtGlweCiphertext<Vec<ValueT>>> =
        vec![DcrtGlweCiphertext::zero(rns_glwe_len); 256];

    expand_key.expand_partial_coefficients_inplace(
        &c1,
        &mut c_expand,
        &domain,
        &mut expand_context,
    );

    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        let m_dec = dcrt_sk.decrypt(cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }
}

/// Test parallel coefficient expansion in the NTT (DCRT) domain.
///
/// Same as [`test_dcrt_glwe_expand_coefficients`] but uses the
/// multi-threaded parallel expansion via a shared context pool.
#[test]
fn test_dcrt_glwe_expand_coefficients_parallel() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

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

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let expand_key = DcrtGlweExpandCoeffKey::new(&domain, &dcrt_sk, &mut rng);

    // ── Thread-safe context pool for parallel expansion ─────────
    let context_pool =
        DcrtGlweExpandCoeffSyncPool::with_capacity(rayon::current_num_threads(), &domain);

    // ── Encrypt ─────────────────────────────────────────────────
    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<DcrtGlweCiphertext<Vec<ValueT>>> =
        vec![DcrtGlweCiphertext::zero(rns_glwe_len); poly_length];
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── Full parallel expansion ─────────────────────────────────
    expand_key.expand_coefficients_inplace_parallel(&c1, &mut c_expand, &domain, &context_pool);

    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        let m_dec = dcrt_sk.decrypt(cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // ── Partial parallel expansion (first 256) ──────────────────
    input1[256..].fill(0);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let mut c_expand: Vec<DcrtGlweCiphertext<Vec<ValueT>>> =
        vec![DcrtGlweCiphertext::zero(rns_glwe_len); 256];

    expand_key.expand_partial_coefficients_inplace_parallel(
        &c1,
        &mut c_expand,
        &domain,
        &context_pool,
    );

    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        let m_dec = dcrt_sk.decrypt(cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }
}

/// Test parallel coefficient expansion in the coefficient (CRT) domain.
///
/// Same as [`test_crt_glwe_expand_coefficients`] but uses the
/// multi-threaded parallel expansion via a shared context pool.
/// Requires conversion from NTT to coefficient domain before expansion.
#[test]
fn test_crt_glwe_expand_coefficients_parallel() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

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

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let expand_key = CrtGlweExpandCoeffKey::new(&domain, &sk, &dcrt_sk, &mut rng);

    let context_pool =
        CrtGlweExpandCoeffSyncPool::with_capacity(rayon::current_num_threads(), &domain);

    // ── Encrypt ─────────────────────────────────────────────────
    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<CrtGlwe<Vec<ValueT>>> = vec![CrtGlwe::zero(rns_glwe_len); poly_length];
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);
    assert_eq!(m_dec, input1);

    // ── Full parallel expansion (requires coefficient domain) ───
    let c1 = c1.into_coeff_form(&table);

    expand_key.expand_coefficients_inplace_parallel(&c1, &mut c_expand, &domain, &context_pool);

    for (cipher, &input) in c_expand.into_iter().zip(input1.iter()) {
        let cipher = cipher.into_ntt_form(&table);
        let m_dec = dcrt_sk.decrypt(&cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // ── Partial parallel expansion (first 256) ──────────────────
    let mut c1 = DcrtGlweCiphertext::new(c1.0);

    input1[256..].fill(0);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let c1 = c1.into_coeff_form(&table);

    let mut c_expand: Vec<CrtGlwe<Vec<ValueT>>> = vec![CrtGlwe::zero(rns_glwe_len); 256];

    expand_key.expand_partial_coefficients_inplace_parallel(
        &c1,
        &mut c_expand,
        &domain,
        &context_pool,
    );

    for (cipher, &input) in c_expand.into_iter().zip(input1.iter()) {
        let cipher = cipher.into_ntt_form(&table);
        let m_dec = dcrt_sk.decrypt(&cipher, &glwe_params, &table, &mut decrypt_context);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }
}
