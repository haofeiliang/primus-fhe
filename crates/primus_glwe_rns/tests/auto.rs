use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweAutoKey, CrtGlweAutomorphismWorkspace, CrtGlweParameters,
    DcrtGadgetDomain, DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweDecryptWorkspace,
    DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::UintDcrtTable;
use primus_poly::Polynomial;
use primus_reduce::ReduceNeg;
use rand::RngExt;
use rand::{SeedableRng, rngs::StdRng};

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
/// against an independent coefficient-domain plaintext automorphism.
#[test]
fn test_crt_glwe_auto() {
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

    let mut auto_degree = rng.random_range(0..poly_length * 2);
    if auto_degree & 1 == 0 {
        auto_degree |= 1; // automorphism degree must be odd (coprime to 2N)
    }

    let auto_key = CrtGlweAutoKey::new(&domain, auto_degree, &sk, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlwe<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: CrtGlwe<Vec<ValueT>> = CrtGlwe::zero(rns_glwe_len);
    let mut auto_workspace = CrtGlweAutomorphismWorkspace::new(&domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    // Sanity: decrypt original
    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_workspace);
    assert_eq!(m_dec, input1);

    let c1 = c1.into_coeff_form(&table);

    auto_key.automorphism_to(&c1, &mut c2, &domain, &mut auto_workspace);

    let c2 = c2.into_ntt_form(&table);

    let auto_msg_2 = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_workspace);

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

    let mut auto_degree = rng.random_range(0..poly_length * 2);
    if auto_degree & 1 == 0 {
        auto_degree |= 1;
    }

    let auto_key = DcrtGlweAutoKey::new(&domain, auto_degree, &dcrt_sk, &mut rng);

    let input1: Polynomial<Vec<ValueT>> = Polynomial::random(poly_length, mod_t, &mut rng);
    let mut c1: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut c2: DcrtGlweCiphertext<Vec<ValueT>> = DcrtGlweCiphertext::zero(rns_glwe_len);
    let mut auto_workspace = CrtGlweAutomorphismWorkspace::new(&domain);
    let mut decrypt_workspace = DcrtGlweDecryptWorkspace::new(glwe_params.size());

    dcrt_sk.encrypt_plaintext_inplace(&input1, &mut c1, &glwe_params, &table, &mut rng);

    let m_dec = dcrt_sk.decrypt(&c1, &glwe_params, &table, &mut decrypt_workspace);
    assert_eq!(m_dec, input1);

    auto_key.automorphism_to(&c1, &mut c2, &domain, &mut auto_workspace);

    let auto_msg_2 = dcrt_sk.decrypt(&c2, &glwe_params, &table, &mut decrypt_workspace);

    let expected = coefficient_automorphism(input1.as_ref(), auto_degree, mod_t);
    assert_eq!(auto_msg_2.as_ref(), expected);
}
