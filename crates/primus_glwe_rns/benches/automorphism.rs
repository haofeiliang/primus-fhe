use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_glwe_rns::{
    CrtGlevParameters, CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweParameters, DcrtGadgetDomain,
    DcrtGlweAutoKey, DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, SecretKeyDistr,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, U64DcrtTable};
use primus_poly::{CrtPolynomial, Polynomial};

fn bench_automorphism(c: &mut Criterion) {
    type V = u64;

    let dimension = 2;
    let t: V = 12289;
    let mod_t = BarrettModulus::new(t);
    let gamma: V = 2199023190017;
    let mod_gamma = BarrettModulus::new(gamma);
    let moduli_values: [V; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(BarrettModulus::new);
    let auto_degree = 5;

    let mut rng = rand::rng();

    let mut group = c.benchmark_group("automorphism");

    for log_n in [10u32, 11, 12] {
        let poly_length = 1usize << log_n;
        let table = U64DcrtTable::new(log_n, &moduli).unwrap();

        let glwe_params = CrtGlweParameters::new(
            dimension,
            poly_length,
            mod_t,
            mod_gamma,
            &moduli,
            SecretKeyDistr::Ternary,
            3.20,
        );

        let crt_poly_len = glwe_params.rns_poly_len();
        let rns_glwe_len = glwe_params.rns_glwe_len();
        let base_q = glwe_params.base_q();

        let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
        let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

        let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, 20, None);

        let domain = DcrtGadgetDomain::try_new(&glev_params, &table).unwrap();

        let crt_auto_key = CrtGlweAutoKey::new(&domain, auto_degree, &sk, &dcrt_sk, &mut rng);

        let dcrt_auto_key = DcrtGlweAutoKey::new(&domain, auto_degree, &dcrt_sk, &mut rng);

        let table_ref = &table;

        // Ciphertexts
        let input: Polynomial<Vec<V>> = Polynomial::random(poly_length, mod_t, &mut rng);
        let mut msg: CrtPolynomial<Vec<V>> = CrtPolynomial::zero(crt_poly_len);
        let mut c_ntt: DcrtGlwe<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);

        base_q.wrapping_decompose_small_polynomial_to(&input, &mut msg, poly_length, t);
        dcrt_sk.encrypt_inplace(&msg, &mut c_ntt, &glwe_params, table_ref, &mut rng);

        let c_coeff: CrtGlwe<Vec<V>> = {
            let tmp = DcrtGlweCiphertext::new(c_ntt.as_ref().to_vec());
            tmp.into_coeff_form(table_ref)
        };

        // Buffers
        let mut crt_result: CrtGlwe<Vec<V>> = CrtGlwe::zero(rns_glwe_len);
        let mut dcrt_result: DcrtGlweCiphertext<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        let mut auto_context = CrtGlweAutoContext::new(&domain);

        let n_label = format!("N={poly_length}");

        group.bench_with_input(BenchmarkId::new("CRT", &n_label), &(), |b, _| {
            b.iter(|| {
                crt_auto_key.automorphism_to(
                    black_box(&c_coeff),
                    black_box(&mut crt_result),
                    &domain,
                    &mut auto_context,
                );
            });
        });

        group.bench_with_input(BenchmarkId::new("DCRT", &n_label), &(), |b, _| {
            b.iter(|| {
                dcrt_auto_key.automorphism_to(
                    black_box(&c_ntt),
                    black_box(&mut dcrt_result),
                    &domain,
                    &mut auto_context,
                );
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_automorphism);
criterion_main!(benches);
