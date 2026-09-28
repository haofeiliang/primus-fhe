use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweParameters, CrtGlweTraceKey, CrtGlweTraceWorkspace, DcrtGadgetDomain,
    DcrtGlweCiphertext, DcrtGlweDecryptWorkspace, DcrtGlweRevTraceKey, DcrtGlweRevTraceWorkspace,
    DcrtGlweSecretKey, DcrtGlweTraceKey, DcrtGlweTraceWorkspace, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::glwe::CrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_reduce::prelude::*;
use rand::{SeedableRng, rngs::StdRng};

/// Test GLWE trace in the coefficient (CRT) domain.
///
/// Trace decrypts the constant coefficient m₀ of a ciphertext:
///   Trace(c) → Enc(N · m₀),  where N = poly_length.
///
/// Multiplying the input ciphertext by N⁻¹ before the trace recovers
/// the original m₀ directly (without the N factor).
/// Both variants are verified.
#[test]
fn test_crt_glwe_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 1 << 15;
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

    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let trace_key = CrtGlweTraceKey::new(&domain, &sk, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::zero(rns_glwe_len);
    let mut trace_workspace = CrtGlweTraceWorkspace::new(&domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_workspace);
    assert_eq!(m_dec, input1);

    let mut c1 = c1.into_coeff_form(&table);

    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_workspace);

    let c2 = c2.into_ntt_form(&table);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_workspace);

    // trace_msg[0] = N · input1[0]  (mod t)
    assert_eq!(
        mod_t.reduce_mul(input1[0], poly_length as ValueT),
        trace_msg[0]
    );
    // Other coefficients are zero.
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    let scalar_residue = base_q
        .wrapping_decompose(poly_length as ValueT, t)
        .iter()
        .zip(moduli.iter())
        .map(|(&n, m)| m.reduce_inv(n))
        .collect::<Vec<_>>();

    c1.mul_scalar_assign(
        &primus_rns::Residues(scalar_residue.as_slice()),
        poly_length,
        rns_poly_len,
        &moduli,
    );

    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::new(c2.0);

    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_workspace);

    let c2 = c2.into_ntt_form(&table);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_workspace);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}

/// Test GLWE trace in the NTT (DCRT) domain.
///
/// Same as [`test_crt_glwe_trace`] but the ciphertext stays in NTT domain.
#[test]
fn test_dcrt_glwe_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 1 << 15;
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

    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(
        glwe_params.size().glwe_size(),
        glwe_params.secret_key_sampler(),
        &mut rng,
    );
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let trace_key = DcrtGlweTraceKey::new(&domain, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut trace_workspace = DcrtGlweTraceWorkspace::new(&domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_workspace);
    assert_eq!(m_dec, input1);

    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_workspace);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_workspace);

    assert_eq!(
        mod_t.reduce_mul(input1[0], poly_length as ValueT),
        trace_msg[0]
    );
    assert!(trace_msg[1..].iter().all(|&v| v == 0));

    let scalar_residue = base_q
        .wrapping_decompose(poly_length as ValueT, t)
        .iter()
        .zip(moduli.iter())
        .map(|(&n, m)| m.reduce_inv(n))
        .collect::<Vec<_>>();

    c1.mul_scalar_assign(
        &primus_rns::Residues(scalar_residue.as_slice()),
        poly_length,
        rns_poly_len,
        &moduli,
    );

    trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_workspace);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_workspace);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}

/// Test reverse-homomorphic trace in the NTT (DCRT) domain.
///
/// RevHomTrace directly produces an encryption of m₀ (without the N factor),
/// unlike the standard trace which produces N · m₀.
#[test]
fn test_dcrt_glwe_rev_trace() {
    type ValueT = u64;

    let dimension = 2;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 1 << 15;
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

    let rev_trace_key = DcrtGlweRevTraceKey::new(&domain, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut trace_workspace = DcrtGlweRevTraceWorkspace::new(&domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_workspace);
    assert_eq!(m_dec, input1);

    rev_trace_key.trace_inplace(&c1, &mut c2, &domain, &mut trace_workspace);

    let trace_msg = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_workspace);

    assert_eq!(input1[0], trace_msg[0]);
    assert!(trace_msg[1..].iter().all(|&v| v == 0));
}
