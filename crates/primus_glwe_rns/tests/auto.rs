use primus_decompose::DecompositionBaseLog;
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweAutoEvaluator, CrtGlweAutoKey, CrtGlweParameters, DcrtGadgetDomain,
    DcrtGlweAutoEvaluator, DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::GlweDimension;
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::{PolyLength, Polynomial};
use primus_reduce::ReduceNeg;
use rand::{SeedableRng, rngs::StdRng};

// Scatter m_i to X^(i*degree), applying the sign from reduction modulo X^N+1.
// This oracle does not use the ciphertext permutation or its cached index table.
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
/// Reuse ciphertext storage across identity, N+1 and a general odd degree.
/// Reuse each evaluator twice, checking decryption against an independent
/// coefficient-domain plaintext automorphism.
#[test]
fn test_crt_glwe_auto() {
    type ValueT = u64;

    let dimension = 3;
    let poly_length: usize = 32;
    let log_n = poly_length.trailing_zeros();
    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);

    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(PolyLength::new(1usize << log_n), &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
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

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::zero(rns_glwe_len);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

    let c1 = c1.into_coeff_form(&table);

    let mut transformed = DcrtGlweCiphertext::<Vec<ValueT>>::zero(rns_glwe_len);
    for degree in [1, poly_length + 1, 3] {
        let auto_key = CrtGlweAutoKey::new(&domain, degree, &sk, &dcrt_sk, &mut rng);
        let mut evaluator = CrtGlweAutoEvaluator::new(&auto_key, &domain);
        evaluator.automorphism_to(&c1.as_view(), &mut c2.as_mut_view());

        let first = c2.as_ref().to_vec();
        evaluator.automorphism_to(&c1.as_view(), &mut c2.as_mut_view());
        assert_eq!(c2.as_ref(), first);

        c2.write_ntt_form(&mut transformed, &table);
        let actual = dcrt_sk_context.decrypt(&transformed, &mut decrypt_workspace);
        let expected = coefficient_automorphism(input1.as_ref(), degree, mod_t);
        assert_eq!(actual.as_ref(), expected, "degree={degree}");
    }
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
    let poly_length: usize = 32;
    let log_n = poly_length.trailing_zeros();
    let t: ValueT = 12289;
    let mod_t = <BarrettModulus<ValueT>>::new(t);
    let gamma: ValueT = 2199023190017;
    let mod_gamma = <BarrettModulus<ValueT>>::new(gamma);

    let moduli_values: [ValueT; _] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(<BarrettModulus<ValueT>>::new);
    let table = UintDcrtTable::new(PolyLength::new(1usize << log_n), &moduli).unwrap();

    let mut rng = StdRng::seed_from_u64(42);

    let glwe_params = CrtGlweParameters::new(
        GlweDimension::new(dimension),
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

    let glev_params =
        CrtGlevParameters::with_glwe_params(&glwe_params, DecompositionBaseLog::new(20), None);
    let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    let dcrt_sk_context = dcrt_sk.try_bind(&glwe_params, &table).unwrap();
    dcrt_sk_context.encrypt_to(&input1, &mut c1, &mut rng);

    for degree in [1, poly_length + 1, 3] {
        let auto_key = DcrtGlweAutoKey::new(&domain, degree, &dcrt_sk, &mut rng);
        let mut evaluator = DcrtGlweAutoEvaluator::new(&auto_key, &domain);
        evaluator.automorphism_to(&c1.as_view(), &mut c2.as_mut_view());

        let first = c2.as_ref().to_vec();
        evaluator.automorphism_to(&c1.as_view(), &mut c2.as_mut_view());
        assert_eq!(c2.as_ref(), first);

        let actual = dcrt_sk_context.decrypt(&c2, &mut decrypt_workspace);
        let expected = coefficient_automorphism(input1.as_ref(), degree, mod_t);
        assert_eq!(actual.as_ref(), expected, "degree={degree}");
    }
}
