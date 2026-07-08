use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweExpandCoeffContext, CrtGlweExpandCoeffKey,
    CrtGlweExpandCoeffSyncPool, CrtGlweParameters, CrtGlweSecretKey, DcrtGlweCiphertext,
    DcrtGlweExpandCoeffContext, DcrtGlweExpandCoeffKey, DcrtGlweExpandCoeffSyncPool,
    DcrtGlweSecretKey, RingSecretKeyType,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, U64DcrtTable};
use primus_poly::{CrtPolynomial, Polynomial};

fn bench_expand_coeff(c: &mut Criterion) {
    type V = u64;

    let dimension = 2;
    let t: V = 12289;
    let mod_t = BarrettModulus::new(t);
    let gamma: V = 2199023190017;
    let mod_gamma = BarrettModulus::new(gamma);
    let moduli_values: [V; 2] = [1125899906826241, 1125899906629633];
    let moduli = moduli_values.map(BarrettModulus::new);
    let moduli_count = moduli_values.len();

    let mut rng = rand::rng();

    let mut group = c.benchmark_group("expand_coeff");
    group.sample_size(10);

    let current_num_threads = rayon::current_num_threads();

    println!("Max threads count: {}", current_num_threads);

    for log_n in [10u32, 11, 12] {
        let poly_length = 1usize << log_n;
        let table = U64DcrtTable::new(log_n, &moduli).unwrap();

        let glwe_params = CrtGlweParameters::new(
            dimension,
            poly_length,
            mod_t,
            mod_gamma,
            &moduli,
            RingSecretKeyType::Ternary,
            3.20,
        );

        let crt_poly_len = glwe_params.rns_poly_len();
        let big_uint_poly_len = glwe_params.big_uint_poly_len();
        let rns_glwe_len = glwe_params.rns_glwe_len();
        let base_q = glwe_params.base_q();

        let sk = CrtGlweSecretKey::generate(&glwe_params, &mut rng);
        let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

        let basis = BigUintApproxSignedBasis::new(glwe_params.cipher_modulus(), 20, None, base_q);
        let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, basis);

        let table = Arc::new(table);

        // Expand keys
        let crt_expand_key = CrtGlweExpandCoeffKey::new(
            &glev_params,
            base_q,
            &sk,
            &dcrt_sk,
            Arc::clone(&table),
            &mut rng,
        );

        let dcrt_expand_key = DcrtGlweExpandCoeffKey::new(
            &glev_params,
            base_q,
            &dcrt_sk,
            Arc::clone(&table),
            &mut rng,
        );

        let table_ref = table.as_ref();

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
        let mut crt_result: Vec<CrtGlwe<Vec<V>>> = vec![CrtGlwe::zero(rns_glwe_len); poly_length];
        let mut dcrt_result: Vec<DcrtGlweCiphertext<Vec<V>>> =
            vec![DcrtGlweCiphertext::zero(rns_glwe_len); poly_length];

        let mut crt_ctx = CrtGlweExpandCoeffContext::new(
            dimension,
            poly_length,
            crt_poly_len,
            big_uint_poly_len,
            moduli_count,
        );
        let mut dcrt_ctx = DcrtGlweExpandCoeffContext::new(
            dimension,
            poly_length,
            crt_poly_len,
            big_uint_poly_len,
            moduli_count,
        );

        let crt_pool = CrtGlweExpandCoeffSyncPool::with_capacity(
            current_num_threads,
            dimension,
            poly_length,
            crt_poly_len,
            big_uint_poly_len,
            moduli_count,
        );
        let dcrt_pool = DcrtGlweExpandCoeffSyncPool::with_capacity(
            current_num_threads,
            dimension,
            poly_length,
            crt_poly_len,
            big_uint_poly_len,
            moduli_count,
        );

        let n_label = format!("N={poly_length}");

        // ---- Single-threaded ----
        group.bench_with_input(BenchmarkId::new("CRT/single", &n_label), &(), |b, _| {
            b.iter(|| {
                crt_expand_key.expand_coefficients_inplace(
                    black_box(&c_coeff),
                    black_box(&mut crt_result),
                    &glev_params,
                    base_q,
                    &mut crt_ctx,
                );
            });
        });

        group.bench_with_input(BenchmarkId::new("DCRT/single", &n_label), &(), |b, _| {
            b.iter(|| {
                dcrt_expand_key.expand_coefficients_inplace(
                    black_box(&c_ntt),
                    black_box(&mut dcrt_result),
                    &glev_params,
                    base_q,
                    &mut dcrt_ctx,
                );
            });
        });

        // ---- Multi-threaded ----
        group.bench_with_input(BenchmarkId::new("CRT/parallel", &n_label), &(), |b, _| {
            b.iter(|| {
                crt_expand_key.expand_coefficients_inplace_parallel(
                    black_box(&c_coeff),
                    black_box(&mut crt_result),
                    &glev_params,
                    base_q,
                    &crt_pool,
                );
            });
        });

        group.bench_with_input(BenchmarkId::new("DCRT/parallel", &n_label), &(), |b, _| {
            b.iter(|| {
                dcrt_expand_key.expand_coefficients_inplace_parallel(
                    black_box(&c_ntt),
                    black_box(&mut dcrt_result),
                    &glev_params,
                    base_q,
                    &dcrt_pool,
                );
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_expand_coeff);
criterion_main!(benches);
