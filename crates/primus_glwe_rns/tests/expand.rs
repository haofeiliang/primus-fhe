//! Compare sequential and two-worker expansion on the same keys and ciphertexts.
//! N=32 retains a multi-level tree; two ~50-bit limbs retain wide CRT arithmetic.
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweExpandCoeffKey, CrtGlweExpandCoeffSyncPool,
    CrtGlweExpandCoeffWorkspace, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweCiphertext,
    DcrtGlweDecryptWorkspace, DcrtGlweExpandCoeffKey, DcrtGlweExpandCoeffSyncPool,
    DcrtGlweExpandCoeffWorkspace, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::glwe::CrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use rand::{SeedableRng, rngs::StdRng};

/// Test coefficient expansion in the coefficient (CRT) domain.
///
/// Expands a GLWE ciphertext encrypting m(X) into N ciphertexts,
/// one per coefficient: the i-th output encrypts m_i (the i-th coefficient).
/// Verifies full expansion (all N coefficients) and partial expansion (first N/2 coefficients).
#[test]
fn crt_expansion_matches_parallel_and_plaintext() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 32;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let expand_key = CrtGlweExpandCoeffKey::new(&domain, &sk, &dcrt_sk, &mut rng);

    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<CrtGlwe<Vec<ValueT>>> = vec![CrtGlwe::zero(rns_glwe_len); poly_length];
    let mut expand_workspace = CrtGlweExpandCoeffWorkspace::new(&domain);
    let workspace_pool = CrtGlweExpandCoeffSyncPool::with_capacity(2, &domain);
    let mut parallel_output = c_expand.clone();
    // Use a local pool so this small correctness test does not create a worker
    // per CI core. Both expansion trees reuse these two scratch workspaces.
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());
    let mut transformed = DcrtGlweCiphertext::<Vec<ValueT>>::zero(rns_glwe_len);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    // Requires conversion to coefficient domain first.
    let c1 = c1.into_coeff_form(&table);

    expand_key.expand_coefficients_inplace(&c1, &mut c_expand, &domain, &mut expand_workspace);
    workers.install(|| {
        expand_key.expand_coefficients_inplace_parallel(
            &c1,
            &mut parallel_output,
            &domain,
            &workspace_pool,
        );
    });
    for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
        assert_eq!(sequential.as_ref(), parallel.as_ref());
    }

    // Each output decrypts to (m_i, 0, …, 0)
    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        cipher.write_ntt_form(&mut transformed, &table);
        let m_dec = dcrt_sk.decrypt(&transformed, &glwe_params, &table, &mut decrypt_workspace);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // Wraps back to DCRT domain, zeros out high coefficients, re-encrypts.
    let mut c1 = DcrtGlweCiphertext::new(c1.0);

    // Partial expansion assumes the omitted coefficients are zero. Reuse dirty
    // output buffers and both workspaces from the full expansion.
    let retained = poly_length / 2;
    input1[retained..].fill(0);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let c1 = c1.into_coeff_form(&table);

    c_expand.truncate(retained);
    parallel_output.truncate(retained);

    expand_key.expand_partial_coefficients_inplace(
        &c1,
        &mut c_expand,
        &domain,
        &mut expand_workspace,
    );
    workers.install(|| {
        expand_key.expand_partial_coefficients_inplace_parallel(
            &c1,
            &mut parallel_output,
            &domain,
            &workspace_pool,
        );
    });
    for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
        assert_eq!(sequential.as_ref(), parallel.as_ref());
    }

    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        cipher.write_ntt_form(&mut transformed, &table);
        let m_dec = dcrt_sk.decrypt(&transformed, &glwe_params, &table, &mut decrypt_workspace);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }
}

/// Test coefficient expansion in the NTT (DCRT) domain.
///
/// Same as [`crt_expansion_matches_parallel_and_plaintext`] but the ciphertext stays
/// in the NTT domain — no conversion to coefficient form required.
#[test]
fn dcrt_expansion_matches_parallel_and_plaintext() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 32;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(log_n, &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        dimension,
        poly_length,
        mod_t,
        mod_gamma,
        &moduli,
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let expand_key = DcrtGlweExpandCoeffKey::new(&domain, &dcrt_sk, &mut rng);

    let mut input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c_expand: Vec<DcrtGlweCiphertext<Vec<ValueT>>> =
        vec![DcrtGlweCiphertext::zero(rns_glwe_len); poly_length];
    let mut expand_workspace = DcrtGlweExpandCoeffWorkspace::new(&domain);
    let workspace_pool = DcrtGlweExpandCoeffSyncPool::with_capacity(2, &domain);
    let mut parallel_output = c_expand.clone();
    // Use a local pool so this small correctness test does not create a worker
    // per CI core. Both expansion trees reuse these two scratch workspaces.
    let workers = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap();
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    expand_key.expand_coefficients_inplace(&c1, &mut c_expand, &domain, &mut expand_workspace);
    workers.install(|| {
        expand_key.expand_coefficients_inplace_parallel(
            &c1,
            &mut parallel_output,
            &domain,
            &workspace_pool,
        );
    });
    for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
        assert_eq!(sequential.as_ref(), parallel.as_ref());
    }

    // Results are already in NTT domain — decrypt directly.
    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        let m_dec = dcrt_sk.decrypt(cipher, &glwe_params, &table, &mut decrypt_workspace);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }

    // Partial expansion assumes the omitted coefficients are zero. Reuse dirty
    // output buffers and both workspaces from the full expansion.
    let retained = poly_length / 2;
    input1[retained..].fill(0);

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    c_expand.truncate(retained);
    parallel_output.truncate(retained);

    expand_key.expand_partial_coefficients_inplace(
        &c1,
        &mut c_expand,
        &domain,
        &mut expand_workspace,
    );
    workers.install(|| {
        expand_key.expand_partial_coefficients_inplace_parallel(
            &c1,
            &mut parallel_output,
            &domain,
            &workspace_pool,
        );
    });
    for (sequential, parallel) in c_expand.iter().zip(&parallel_output) {
        assert_eq!(sequential.as_ref(), parallel.as_ref());
    }

    for (cipher, &input) in c_expand.iter().zip(input1.iter()) {
        let m_dec = dcrt_sk.decrypt(cipher, &glwe_params, &table, &mut decrypt_workspace);
        assert_eq!(input, m_dec[0]);
        assert!(m_dec[1..].iter().all(|&v| v == 0));
    }
}
