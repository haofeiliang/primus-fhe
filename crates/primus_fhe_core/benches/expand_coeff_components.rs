use std::hint::black_box;
use std::sync::Arc;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_factor::ShoupFactor;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweAutoContext, CrtGlweAutoKey, CrtGlweParameters, DcrtGlweAutoKey,
    DcrtGlweCiphertext, DcrtGlweSecretKey, GlweSecretKey, RingSecretKeyType,
};
use primus_integer::BigUint;
use primus_lattice::glwe::{CrtGlwe, DcrtGlwe};
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, U64DcrtTable};
use primus_poly::{CrtPolynomial, Polynomial};
use primus_reduce::ReduceInv;

fn bench_expand_coeff_components(c: &mut Criterion) {
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

    let mut group = c.benchmark_group("expand_coeff_components");
    group.sample_size(10);

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

        let sk = GlweSecretKey::generate(&glwe_params, &mut rng);
        let dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&sk, &table);

        let basis = BigUintApproxSignedBasis::new(glwe_params.cipher_modulus(), 20, None, base_q);
        let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, basis);

        let table = Arc::new(table);
        let table_ref = table.as_ref();

        let auto_degree = poly_length + 1;
        let crt_auto_key = CrtGlweAutoKey::new(
            &glev_params,
            auto_degree,
            &sk,
            &dcrt_sk,
            Arc::clone(&table),
            &mut rng,
        );
        let dcrt_auto_key = DcrtGlweAutoKey::new(
            &glev_params,
            auto_degree,
            &dcrt_sk,
            Arc::clone(&table),
            &mut rng,
        );

        let input: Polynomial<Vec<V>> = Polynomial::random(poly_length, mod_t, &mut rng);
        let mut msg: CrtPolynomial<Vec<V>> = CrtPolynomial::zero(crt_poly_len);
        let mut c_ntt: DcrtGlwe<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);

        base_q.wrapping_decompose_small_polynomial_to(&input, &mut msg, poly_length, t);
        dcrt_sk.encrypt_inplace(&msg, &mut c_ntt, &glwe_params, table_ref, &mut rng);

        let c_coeff: CrtGlwe<Vec<V>> = {
            let tmp = DcrtGlweCiphertext::new(c_ntt.as_ref().to_vec());
            tmp.into_coeff_form(table_ref)
        };

        let inv_count_residues = {
            let mut count = vec![0; glev_params.big_uint_value_len()];
            count[0] = poly_length as V;
            let count_residue = base_q.decompose(BigUint(&count));
            count_residue
                .iter()
                .zip(base_q.moduli())
                .map(|(&n, m)| ShoupFactor::new(m.reduce_inv(n), m.value()))
                .collect::<Vec<_>>()
        };

        let monomial_factors = {
            let mut monomial_ntt = vec![0; crt_poly_len];
            table_ref.transform_coeff_one_monomial(poly_length * 2 - 1, &mut monomial_ntt);
            monomial_ntt
                .chunks_exact(poly_length)
                .zip(moduli_values)
                .flat_map(|(poly, modulus)| {
                    poly.iter()
                        .map(move |&value| ShoupFactor::new(value, modulus))
                })
                .collect::<Vec<_>>()
        };

        let mut crt_auto_context =
            CrtGlweAutoContext::new(poly_length, crt_poly_len, big_uint_poly_len, moduli_count);
        let mut dcrt_auto_context =
            CrtGlweAutoContext::new(poly_length, crt_poly_len, big_uint_poly_len, moduli_count);
        let mut crt_auto_result: CrtGlwe<Vec<V>> = CrtGlwe::zero(rns_glwe_len);
        let mut dcrt_auto_result: DcrtGlweCiphertext<Vec<V>> =
            DcrtGlweCiphertext::zero(rns_glwe_len);

        crt_auto_key.automorphism_to(
            &c_coeff,
            &mut crt_auto_result,
            &glev_params,
            base_q,
            &mut crt_auto_context,
        );
        dcrt_auto_key.automorphism_to(
            &c_ntt,
            &mut dcrt_auto_result,
            &glev_params,
            base_q,
            &mut dcrt_auto_context,
        );

        let n_label = format!("N={poly_length}");

        group.bench_with_input(
            BenchmarkId::new("DCRT/init_scale", &n_label),
            &(),
            |b, _| {
                let mut scale_result: DcrtGlweCiphertext<Vec<V>> =
                    DcrtGlweCiphertext::zero(rns_glwe_len);
                b.iter(|| {
                    c_ntt.mul_factor_to(
                        black_box(&inv_count_residues),
                        black_box(&mut scale_result),
                        poly_length,
                        crt_poly_len,
                        &moduli_values,
                    );
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("CRT/automorphism", &n_label),
            &(),
            |b, _| {
                let mut result: CrtGlwe<Vec<V>> = CrtGlwe::zero(rns_glwe_len);
                let mut context = CrtGlweAutoContext::new(
                    poly_length,
                    crt_poly_len,
                    big_uint_poly_len,
                    moduli_count,
                );
                b.iter(|| {
                    crt_auto_key.automorphism_to(
                        black_box(&c_coeff),
                        black_box(&mut result),
                        &glev_params,
                        base_q,
                        &mut context,
                    );
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("DCRT/automorphism", &n_label),
            &(),
            |b, _| {
                let mut result: DcrtGlweCiphertext<Vec<V>> = DcrtGlweCiphertext::zero(rns_glwe_len);
                let mut context = CrtGlweAutoContext::new(
                    poly_length,
                    crt_poly_len,
                    big_uint_poly_len,
                    moduli_count,
                );
                b.iter(|| {
                    dcrt_auto_key.automorphism_to(
                        black_box(&c_ntt),
                        black_box(&mut result),
                        &glev_params,
                        base_q,
                        &mut context,
                    );
                });
            },
        );

        group.bench_with_input(BenchmarkId::new("CRT/post_step", &n_label), &(), |b, _| {
            b.iter_batched_ref(
                || (c_coeff.clone(), CrtGlwe::<Vec<V>>::zero(rns_glwe_len)),
                |batch| {
                    let a_0 = &mut batch.0;
                    let b_0 = &mut batch.1;
                    a_0.sub_element_wise_to(
                        black_box(&crt_auto_result),
                        b_0,
                        poly_length,
                        crt_poly_len,
                        &moduli,
                    );
                    b_0.mul_monic_monomial_assign(
                        poly_length * 2 - 1,
                        poly_length,
                        crt_poly_len,
                        &moduli,
                    );
                    a_0.add_element_wise_assign(
                        black_box(&crt_auto_result),
                        poly_length,
                        crt_poly_len,
                        &moduli,
                    );
                },
                BatchSize::LargeInput,
            );
        });

        group.bench_with_input(
            BenchmarkId::new("DCRT/shoup_butterfly", &n_label),
            &(),
            |b, _| {
                b.iter_batched_ref(
                    || {
                        (
                            c_ntt.clone(),
                            DcrtGlweCiphertext::<Vec<V>>::zero(rns_glwe_len),
                        )
                    },
                    |batch| {
                        let a_0 = &mut batch.0;
                        let b_0 = &mut batch.1;
                        a_0.butterfly_mul_factor_to(
                            black_box(&dcrt_auto_result),
                            black_box(&monomial_factors),
                            b_0,
                            poly_length,
                            &moduli_values,
                        );
                    },
                    BatchSize::LargeInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_expand_coeff_components);
criterion_main!(benches);
