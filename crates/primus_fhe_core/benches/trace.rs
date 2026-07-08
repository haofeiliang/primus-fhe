use std::hint::black_box;
use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweParameters, CrtGlweSecretKey, CrtGlweTraceContext, CrtGlweTraceKey,
    DcrtGlweCiphertext, DcrtGlweRevTraceContext, DcrtGlweRevTraceKey, DcrtGlweSecretKey,
    DcrtGlweTraceContext, DcrtGlweTraceKey, RingSecretKeyType,
};
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, U64DcrtTable};
use primus_poly::{CrtPolynomial, Polynomial};

fn bench_trace(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("trace");

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

        // Trace keys
        let crt_trace_key =
            CrtGlweTraceKey::new(&glev_params, &sk, &dcrt_sk, Arc::clone(&table), &mut rng);

        let dcrt_trace_key =
            DcrtGlweTraceKey::new(&glev_params, &dcrt_sk, Arc::clone(&table), &mut rng);

        let dcrt_rev_trace_key =
            DcrtGlweRevTraceKey::new(&glev_params, &dcrt_sk, Arc::clone(&table), &mut rng);

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
        let mut crt_result: CrtGlwe<Vec<V>> = CrtGlwe::zero(rns_glwe_len);
        let mut dcrt_result: DcrtGlweCiphertext<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        let mut crt_trace_ctx = CrtGlweTraceContext::new(
            dimension,
            poly_length,
            crt_poly_len,
            big_uint_poly_len,
            moduli_count,
        );
        let mut dcrt_trace_ctx = DcrtGlweTraceContext::new(
            dimension,
            poly_length,
            crt_poly_len,
            big_uint_poly_len,
            moduli_count,
        );
        let mut dcrt_rev_trace_ctx = DcrtGlweRevTraceContext::new(
            dimension,
            poly_length,
            crt_poly_len,
            big_uint_poly_len,
            moduli_count,
        );

        let n_label = format!("N={poly_length}");

        group.bench_with_input(BenchmarkId::new("CRT", &n_label), &(), |b, _| {
            b.iter(|| {
                crt_trace_key.trace_inplace(
                    black_box(&c_coeff),
                    black_box(&mut crt_result),
                    &glev_params,
                    base_q,
                    &mut crt_trace_ctx,
                );
            });
        });

        group.bench_with_input(BenchmarkId::new("DCRT", &n_label), &(), |b, _| {
            b.iter(|| {
                dcrt_trace_key.trace_inplace(
                    black_box(&c_ntt),
                    black_box(&mut dcrt_result),
                    &glev_params,
                    base_q,
                    &mut dcrt_trace_ctx,
                );
            });
        });

        group.bench_with_input(BenchmarkId::new("RevHomTrace", &n_label), &(), |b, _| {
            b.iter(|| {
                dcrt_rev_trace_key.trace_inplace(
                    black_box(&c_ntt),
                    black_box(&mut dcrt_result),
                    &glev_params,
                    base_q,
                    &mut dcrt_rev_trace_ctx,
                );
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_trace);
criterion_main!(benches);
