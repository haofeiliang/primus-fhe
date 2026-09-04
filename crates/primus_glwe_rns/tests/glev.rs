use itertools::izip;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweParameters, DcrtGadgetDomain, DcrtGlweDecryptContext,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::{context::DcrtGlevMulContext, glev::DcrtGlev, glwe::DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::{BigUintPolynomial, CrtPolynomial, DcrtPolynomial, Polynomial};

/// Test GLev–BigUint multiplication correctness.
///
/// Given two plaintexts m₁(X), m₂(X), the test verifies that:
///   GLev(m₁) ⊡ CRT(δ·m₂)  decrypts to  m₁ · m₂ mod t
///
/// m₁ is encrypted as a GLev gadget (key-switching key format).
/// m₂ is CRT-encoded with delta scaling and composed into a BigUint polynomial.
/// The GLev–BigUint product is a single GLWE ciphertext encrypting the product.
#[test]
fn test_rns_glev() {
    type ValueT = u64;

    let dimension = 3;
    let poly_length: usize = 512;
    let log_n = poly_length.trailing_zeros();

    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; 2] = [1125899906826241, 1125899906629633];
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
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();
    let rns_poly_len = glwe_params.rns_poly_len();
    let big_uint_poly_len = glwe_params.big_uint_poly_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();
    let rns_glev_len = glev_params.rns_glev_len();

    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());
    let mut glev_context = DcrtGlevMulContext::new(glev_params.size(), glev_params.base_q());

    let mut dcrt_glev: DcrtGlev<Vec<ValueT>> = DcrtGlev::zero(rns_glev_len);

    // ── Two random plaintexts and their expected product ────────
    let mut desired: Polynomial<Vec<ValueT>> = Polynomial::zero(poly_length);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let input2: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);

    input1.naive_mul_to(&input2, &mut desired, mod_t);

    // ── Build GLev gadget encrypting m₁ ─────────────────────────
    // input1 is decomposed into CRT form and encrypted as a GLev structure.
    let mut msg1: CrtPolynomial<Vec<ValueT>> = CrtPolynomial::zero(rns_poly_len);
    base_q.wrapping_decompose_small_polynomial_to(&input1, &mut msg1, t);

    dcrt_sk.encrypt_crt_msg_to_dcrt_glev_inplace(&msg1, &mut dcrt_glev, &domain, &mut rng);

    // ── Build BigUint polynomial encoding m₂ ────────────────────
    // m₂ is decomposed into CRT, then scaled by δ (so it represents
    // δ·m₂ mod Q in the RNS basis), then composed into BigUint form.
    let mut msg2_big_uint_poly: BigUintPolynomial<Vec<ValueT>> =
        BigUintPolynomial::zero(big_uint_poly_len);

    let mut msg2: CrtPolynomial<Vec<ValueT>> = CrtPolynomial::zero(rns_poly_len);

    base_q.wrapping_decompose_small_polynomial_to(&input2, &mut msg2, t);

    msg2.mul_factor_assign(
        glwe_params.delta_factor_mod_q(),
        poly_length,
        glwe_params.cipher_moduli_value(),
    );

    base_q.compose_polynomial_to(
        &msg2,
        &mut msg2_big_uint_poly,
        poly_length,
        glev_context.compose_buffer_mut(),
    );

    // ── GLev(m₁) ⊡ BigUint(δ·m₂) → GLWE(m₁·m₂) ────────────────
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlwe::zero(rns_glwe_len);

    dcrt_glev.mul_big_uint_poly_to(
        &msg2_big_uint_poly,
        &mut c1,
        glev_params.basis(),
        &table,
        base_q,
        &mut glev_context,
    );

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_context);

    assert_eq!(m_dec, desired);
}

/// End-to-end key-switching correctness test.
///
/// Constructs a GLev encryption of the secret key (key-switching key format),
/// then manually builds a ciphertext c = (a, b) where b already contains
/// the inner product a·s. The GLev multiplications are then used to
/// "re-encrypt" the inner product, and the result should decrypt to zero.
#[test]
fn test_key_switching() {
    type ValueT = u64;

    let dimension = 3;
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
        SecretKeyDistr::SparseTernary,
        3.20,
    );

    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let rns_poly_len = glwe_params.rns_poly_len();
    let rns_glwe_len = glwe_params.rns_glwe_len();
    let rns_glev_len = glev_params.rns_glev_len();
    let uniform_distrs = glev_params.cipher_moduli_uniform_distr();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    // ── Encrypt each CRT polynomial of sk as a GLev gadget ──────
    // GLev(s_i) is the key-switching key component for the i-th dimension.
    let mut dcrt_glevs: Vec<DcrtGlev<Vec<ValueT>>> = (0..dimension)
        .map(|_| DcrtGlev::zero(rns_glev_len))
        .collect();
    let mut msgs: Vec<CrtPolynomial<Vec<ValueT>>> = (0..dimension)
        .map(|_| CrtPolynomial::zero(rns_poly_len))
        .collect();

    dcrt_sk
        .iter_dcrt_poly()
        .zip(msgs.iter_mut())
        .for_each(|(a, b)| {
            b.as_mut().copy_from_slice(a.0);
            table.inverse_transform_slice(b.as_mut());
        });

    msgs.iter()
        .zip(dcrt_glevs.iter_mut())
        .for_each(|(msg, glev)| {
            dcrt_sk.encrypt_crt_msg_to_dcrt_glev_inplace(msg, glev, &domain, &mut rng);
        });

    // ── Manually build ciphertext c = (a, b) where b = noise + a·s ──
    // a: uniform random polynomials (NTT domain)
    // b: Gaussian noise + sum(a_i · s_i), in NTT domain
    let mut cipher: Vec<DcrtPolynomial<Vec<ValueT>>> = (0..dimension)
        .map(|_| DcrtPolynomial::zero(rns_poly_len))
        .collect();

    let mut b: DcrtPolynomial<Vec<ValueT>> = DcrtPolynomial::zero(rns_poly_len);

    // Sample noise into b
    primus_distr::sample_crt_gaussian_values_to(
        b.as_mut(),
        poly_length,
        &moduli_values,
        glwe_params.noise_distribution(),
        &mut rng,
    );

    table.transform_slice(b.as_mut());

    // Sample uniform a, then b += Σ a_i · s_i
    cipher.iter_mut().for_each(|ai| {
        primus_distr::sample_crt_uniform_values_to(
            ai.as_mut(),
            poly_length,
            uniform_distrs,
            &mut rng,
        );
    });

    dcrt_sk
        .iter_dcrt_poly()
        .zip(cipher.iter())
        .for_each(|(si, ai)| {
            b.add_mul_assign(ai, &si, poly_length, &moduli);
        });

    // ── Convert a polynomials to coefficient domain ──────────────
    let cipher: Vec<_> = cipher
        .into_iter()
        .map(|a| table.inverse_transform_inplace(a))
        .collect();

    // ── GLev(a_i) ⊡ GLev(s_i) → sum the results ────────────────
    // Each GLev multiplication produces a GLWE ciphertext;
    // we accumulate them and subtract from the original (a, b).
    let mut cs: Vec<DcrtGlwe<Vec<ValueT>>> = (0..dimension)
        .map(|_| DcrtGlwe::zero(rns_glwe_len))
        .collect();

    let mut glev_context = DcrtGlevMulContext::new(glev_params.size(), glev_params.base_q());
    izip!(dcrt_glevs.iter(), cipher.iter(), cs.iter_mut()).for_each(|(glev, ai, result)| {
        glev.mul_crt_poly_to(
            ai,
            result,
            glev_params.basis(),
            &table,
            glwe_params.base_q(),
            &mut glev_context,
        );
    });

    // ── result = (a, b) − Σ GLev(a_i) ⊡ GLev(s_i) ───────────────
    let mut res: DcrtGlwe<Vec<ValueT>> = DcrtGlwe::zero(rns_glwe_len);

    let (_, b_) = res.a_b_mut_slices(glev_params.rns_poly_len());
    b_.copy_from_slice(b.as_ref());

    let result = cs.iter().fold(res, |mut acc, x| {
        acc.sub_element_wise_assign(x, poly_length, rns_poly_len, &moduli);
        acc
    });

    // ── Decrypt: should be zero (noise only) ────────────────────
    let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());
    let m_dec = dcrt_sk.decrypt(&result, &glwe_params, &table, &mut decrypt_context);

    println!("{:?}", m_dec.as_ref());
}
