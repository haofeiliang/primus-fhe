// cargo bench -p primus_fhe_core --bench key_switching

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use primus_decompose::big_integer::BigUintApproxSignedBasis;
use primus_fhe_core::{
    CrtGlevParameters, CrtGlweKeySwitchingContext, CrtGlweKeySwitchingKey, CrtGlweParameters,
    CrtGlweSecretKey, DcrtGlweCiphertext, DcrtGlweDecryptContext, DcrtGlweSecretKey,
    HybridCrtGlweKeySwitchingContext, HybridCrtGlweKeySwitchingKey, RingSecretKeyType,
};
use primus_lattice::glwe::DcrtGlwe;
use primus_modulus::BarrettModulus;
use primus_ntt::{DcrtTable, U64DcrtTable};
use primus_poly::Polynomial;
use primus_rns::HybridRNS;

fn bench_key_switching(c: &mut Criterion) {
    type Value = u64;

    const DIMENSION: usize = 1;
    const PLAINTEXT_MODULUS: Value = 2;
    const GAMMA: Value = 2_305_843_009_213_554_689;
    const Q_VALUES: [Value; 2] = [1_125_899_906_826_241, 1_125_899_906_629_633];
    const P_VALUES: [Value; 2] = [1_125_899_906_031_617, 1_125_899_904_679_937];
    const DECOMPOSITION_BASE_LOG: u32 = 20;
    const HYBRID_CASES: [(&str, usize); 2] = [("grouped", 1), ("singleton", 2)];

    let mod_t = BarrettModulus::new(PLAINTEXT_MODULUS);
    let mod_gamma = BarrettModulus::new(GAMMA);
    let q_moduli = Q_VALUES.map(BarrettModulus::new);
    let p_moduli = P_VALUES.map(BarrettModulus::new);
    let qp_moduli: Vec<_> = q_moduli.iter().chain(p_moduli.iter()).copied().collect();

    let mut rng = rand::rng();
    let mut group = c.benchmark_group("key_switching");
    group.sample_size(10);

    for log_n in [10u32, 11, 12] {
        let poly_length = 1usize << log_n;
        let q_table = U64DcrtTable::new(log_n, &q_moduli).unwrap();
        let qp_table = U64DcrtTable::new(log_n, &qp_moduli).unwrap();

        let glwe_params = CrtGlweParameters::new(
            DIMENSION,
            poly_length,
            mod_t,
            mod_gamma,
            &q_moduli,
            RingSecretKeyType::Ternary,
            3.20,
        );
        let input_sk = CrtGlweSecretKey::generate(&glwe_params, &mut rng);
        let input_dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&input_sk, &q_table);
        let output_sk = CrtGlweSecretKey::generate(&glwe_params, &mut rng);
        let output_dcrt_sk = DcrtGlweSecretKey::from_coeff_secret_key(&output_sk, &q_table);

        let base_q = glwe_params.base_q();
        let basis = BigUintApproxSignedBasis::new(
            glwe_params.cipher_modulus(),
            DECOMPOSITION_BASE_LOG,
            None,
            base_q,
        );
        let glev_params = CrtGlevParameters::with_glwe_params(&glwe_params, basis);

        // Key generation is intentionally outside the timed region.
        let crt_ksk = CrtGlweKeySwitchingKey::new(
            &input_sk,
            &glwe_params,
            &output_dcrt_sk,
            &glev_params,
            &q_table,
            &mut rng,
        );
        let rns_glwe_len = glwe_params.rns_glwe_len();
        let input: Polynomial<Vec<Value>> = Polynomial::random(poly_length, mod_t, &mut rng);
        let mut input_ciphertext: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        input_dcrt_sk.encrypt_plaintext_inplace(
            &input,
            &mut input_ciphertext,
            &glwe_params,
            &q_table,
            &mut rng,
        );
        let input_coeff = input_ciphertext.into_coeff_form(&q_table);

        let mut crt_output: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(rns_glwe_len);
        let mut crt_context = CrtGlweKeySwitchingContext::new(
            poly_length,
            glwe_params.rns_poly_len(),
            glwe_params.big_uint_poly_len(),
            glwe_params.cipher_moduli_count(),
        );
        // Validate the CRT path before measuring it.
        crt_ksk.key_swithching_inplace(
            &input_coeff,
            &mut crt_output,
            glev_params.basis(),
            &q_table,
            base_q,
            &mut crt_context,
        );
        let mut decrypt_context =
            DcrtGlweDecryptContext::new(glwe_params.cipher_moduli_count(), poly_length);
        assert_eq!(
            output_dcrt_sk.decrypt(&crt_output, &glwe_params, &q_table, &mut decrypt_context),
            input,
        );
        group.throughput(Throughput::Elements(poly_length as u64));
        let n_label = format!("N={poly_length}");

        group.bench_with_input(
            BenchmarkId::new("CRT-bit-decomposition", &n_label),
            &(),
            |b, _| {
                b.iter(|| {
                    crt_ksk.key_swithching_inplace(
                        black_box(&input_coeff),
                        black_box(&mut crt_output),
                        black_box(glev_params.basis()),
                        black_box(&q_table),
                        black_box(base_q),
                        black_box(&mut crt_context),
                    );
                });
            },
        );

        for (partition_label, decomposition_count) in HYBRID_CASES {
            let hybrid_params = HybridRNS::new(&q_moduli, &p_moduli, decomposition_count).unwrap();
            let hybrid_ksk = HybridCrtGlweKeySwitchingKey::new(
                &input_sk,
                &glwe_params,
                &output_dcrt_sk,
                &hybrid_params,
                &qp_table,
                &mut rng,
            );
            let mut hybrid_output: DcrtGlwe<Vec<Value>> = DcrtGlweCiphertext::zero(rns_glwe_len);
            let mut hybrid_context =
                HybridCrtGlweKeySwitchingContext::new(&hybrid_ksk, &hybrid_params);

            hybrid_ksk.key_switch_inplace(
                &input_coeff,
                &mut hybrid_output,
                &hybrid_params,
                &qp_table,
                &mut hybrid_context,
            );
            assert_eq!(
                output_dcrt_sk.decrypt(
                    &hybrid_output,
                    &glwe_params,
                    &q_table,
                    &mut decrypt_context,
                ),
                input,
            );

            group.bench_with_input(
                BenchmarkId::new(format!("Hybrid-RNS-{partition_label}"), &n_label),
                &(),
                |b, _| {
                    b.iter(|| {
                        hybrid_ksk.key_switch_inplace(
                            black_box(&input_coeff),
                            black_box(&mut hybrid_output),
                            black_box(&hybrid_params),
                            black_box(&qp_table),
                            black_box(&mut hybrid_context),
                        );
                    });
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, bench_key_switching);
criterion_main!(benches);
