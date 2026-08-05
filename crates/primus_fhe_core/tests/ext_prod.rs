use primus_fhe_core::{
    glwe::{GlweSecretKey, RingSecretKeyType},
    rns_fhe::{
        CrtGlevParameters, CrtGlweParameters, DcrtGlweCiphertext, DcrtGlweDecryptContext,
        DcrtGlwePublicKey, DcrtGlweSecretKey,
    },
};
use primus_lattice::{context::DcrtGlevMulContext, glwe::DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, UintDcrtTable};
use primus_poly::Polynomial;
use primus_reduce::ReduceNegSlice;
use rand::RngExt;

/// Test GLWE external product: c₂ = GGSW(monomial) ⊡ GLWE(plaintext).
///
/// Given an encrypted monomial X^d (as a GGSW) and an encrypted plaintext m(X)
/// (as a GLWE), the external product yields an encryption of m(X) · X^d mod t,
/// i.e. the plaintext rotated right by d with sign-flip on the first d coefficients.
#[test]
fn test_external_product() {
    type ValueT = u64;

    let dimension = 8;
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
        RingSecretKeyType::Ternary,
        3.20,
    );

    let rns_glwe_len = glwe_params.rns_glwe_len();
    let base_q = glwe_params.base_q();

    let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
    let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

    // ── Decomposition basis and public key ──────────────────────
    let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 30, None);

    let pk = DcrtGlwePublicKey::new(&dcrt_sk, &glwe_params, &table, &mut rng);

    // Run 20 iterations with random messages and rotation degrees.
    for _ in 0..20 {
        let degree = rng.random_range(0..poly_length);

        // ── GGSW encrypts the monomial X^d ──────────────────────
        let ggsw = pk.encrypt_monomial_ggsw(&[1, 1], degree, &glev_params, &table, &mut rng);

        // ── Encrypt a random plaintext m(X) ─────────────────────
        let input: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
        let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        let mut c2: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);

        let mut glev_context = DcrtGlevMulContext::new(glev_params.size(), glev_params.base_q());
        let mut decrypt_context = DcrtGlweDecryptContext::new(glwe_params.size());

        dcrt_sk.encrypt_plaintext_inplace(&input, &mut c1, &glwe_params, &table, &mut rng);

        // ── External product: GGSW ⊡ GLWE → rotated plaintext ───
        // Requires coefficient-domain input.
        let c1 = c1.into_coeff_form(&table);

        c1.mul_dcrt_ggsw_to(
            &ggsw,
            &mut c2,
            glev_params.basis(),
            &table,
            base_q,
            &mut glev_context,
        );

        // ── Expected: m(X)·X^d = rotate_right(d) with first d coeffs negated ──
        let mut input_rt = input.clone();
        input_rt.as_mut_slice().rotate_right(degree);
        mod_t.reduce_neg_slice_assign(&mut input_rt.as_mut_slice()[..degree]);

        let output = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_context);

        assert_eq!(input_rt.as_ref(), output.as_ref());
    }
}
