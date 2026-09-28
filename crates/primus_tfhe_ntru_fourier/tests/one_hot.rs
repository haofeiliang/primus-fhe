use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruExternalProductWorkspace, NlevParameters, NtruCiphertext,
    NtruParameters, SecretKeyDistr,
};
use primus_test_allocations as allocations;
use primus_tfhe::ProgrammableBootstrap as _;
use primus_tfhe_ntru_fourier::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig,
    OneHotCircuitBootstrapEvaluator, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
const N: usize = 256;
const Q: u128 = 1u128 << 64;
const M: usize = 4;
const L: usize = 3;

// Independent signed schoolbook phase; checks every coefficient, including tails.
fn phase(cipher: &[u64], secret: &[i64]) -> Vec<u64> {
    let mut result = vec![0i128; N];
    for (i, &c) in cipher.iter().enumerate() {
        for (j, &f) in secret.iter().enumerate() {
            let product = i128::from(c) * i128::from(f);
            if i + j < N {
                result[i + j] += product;
            } else {
                result[i + j - N] -= product;
            }
        }
    }
    result
        .into_iter()
        .map(|v| v.rem_euclid(Q as i128) as u64)
        .collect()
}
fn assert_phase(actual: &[u64], expected: &[u64]) {
    for (&actual, &expected) in actual.iter().zip(expected) {
        let distance = (u128::from(actual) + Q - u128::from(expected)) % Q;
        // Functional fixture tolerance, strictly below the smallest gadget scale.
        assert!(
            distance.min(Q - distance) < 1 << 32,
            "actual={actual}, expected={expected}"
        );
    }
}

fn selectors<Table: FftTable>(distr: SecretKeyDistr) {
    let modulus = primus_modulus::NativeModulus::<u64>::new();
    let full = DecompositionConfig {
        log_basis: 10,
        level_count: None,
    };
    let ring = NtruParameters::new(N, 2 * M as u64, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let tfhe = TfheParameters::try_new(
        LweParameters::new(4, 2 * M as u64, BarrettModulus::new(1u64 << 24), distr, 0.7),
        NlevParameters::with_ntru_params(&ring, 10, None),
        full,
        0.7,
    )
    .unwrap();
    let context = TfheContext::<_, Table, _>::try_from_parameters(tfhe).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4f48434253);
    let (client, server) = context
        .try_generate_keys(
            Some(CircuitBootstrapConfig {
                output: DecompositionConfig {
                    log_basis: 8,
                    level_count: Some(L),
                },
                trace: full,
                trace_noise_standard_deviation: 0.7,
                scheme_switch: full,
                scheme_switch_noise_standard_deviation: 0.7,
            }),
            &mut rng,
        )
        .unwrap();
    let mut evaluator = OneHotCircuitBootstrapEvaluator::try_new(&context, &server).unwrap();
    assert_eq!(evaluator.lookup_table().selector_count(), M);
    assert_eq!(evaluator.lookup_table().rotation_step(), 4);
    let scalars: Vec<_> = evaluator
        .parameters()
        .output_basis()
        .scalar_iter()
        .collect();
    let mut nlev = evaluator.allocate_nlev_output();
    let mut ngsw = evaluator.allocate_ngsw_output();
    let mut nlev_only = nlev.clone();
    let mut ngsw_only = ngsw.clone();
    let mut nonzero_ngsw = evaluator.allocate_nonzero_ngsw_output();
    let selector_len = L * (N / 2);
    assert_eq!(nonzero_ngsw.len(), (M - 1) * selector_len);
    let mut coefficients = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut ep = FourierNtruExternalProductWorkspace::new(N);
    let mut fft = context.new_fft_engine();
    let encryptor = context.encryptor(&client).unwrap();
    let identity = context
        .parameters()
        .compile_lookup_table_fn(|m| m as u64)
        .unwrap();
    let mut lwe_output = primus_tfhe::LweCiphertext::zero(4);
    let mut accumulator = context.accumulator_client(&client).unwrap();
    let choices = [1, 3].map(|m| {
        let mut c = context.allocate_accumulator_ciphertext();
        accumulator.encrypt_to(&[m; N], &mut c, &mut rng);
        c
    });
    let mut transformed_nlev = primus_ntru::FourierNlevCiphertext::<Vec<_>>::zero(L * (N / 2));
    let public = primus_poly::Polynomial::new(vec![(3 * Q / (2 * M) as u128) as u64; N]);
    let mut decoded = vec![0; N];
    // Descending inputs force every selector to overwrite previous nonzero rows.
    for message in (0..M).rev() {
        let input = encryptor.encrypt_padded(message as u64, &mut rng).unwrap();
        let (_, allocation) = allocations::measure(|| {
            evaluator.one_hot_to(&input, &mut nlev, &mut ngsw);
            evaluator
                .bootstrapper_mut()
                .apply_lookup_table_to(&input, &identity, &mut lwe_output);
            evaluator.one_hot_nlev_to(&input, &mut nlev_only);
            evaluator.one_hot_ngsw_to(&input, &mut ngsw_only);
            evaluator.one_hot_nonzero_ngsw_to(&input, &mut nonzero_ngsw);
        });
        assert_eq!(allocation.count, 0);
        assert_eq!(nlev, nlev_only);
        assert_eq!(ngsw, ngsw_only);
        // Compact slot r - 1 must preserve the full-mode selector r, including
        // the all-zero target bits for message 0 and repeated workspace reuse.
        assert_eq!(nonzero_ngsw, ngsw[selector_len..]);
        assert_eq!(
            context
                .decryptor(&client)
                .unwrap()
                .decrypt(&lwe_output)
                .unwrap(),
            message as u64
        );
        for selector in 0..M {
            let bit = u64::from(selector == message);
            let nlev_rows = &nlev[selector * L * N..(selector + 1) * L * N];
            let ngsw_len = L * (N / 2);
            let control =
                FourierNgswCiphertext::new(&ngsw[selector * ngsw_len..(selector + 1) * ngsw_len]);
            for (level, row) in nlev_rows.as_chunks::<N>().0.iter().enumerate() {
                let mut expected = vec![0; N];
                expected[0] = scalars[level] * bit;
                assert_phase(
                    &phase(row, client.accumulator_ntru_secret_key().as_slice()),
                    &expected,
                );
            }
            for (level, row) in control
                .as_ref()
                .as_chunks::<{ N / 2 }>()
                .0
                .iter()
                .enumerate()
            {
                primus_ntru::FourierNtruCiphertext::new(row)
                    .write_torus_form(&mut coefficients, &mut fft);
                let expected: Vec<_> = client
                    .accumulator_ntru_secret_key()
                    .as_slice()
                    .iter()
                    .map(|&f| {
                        (i128::from(f) * i128::from(scalars[level]) * i128::from(bit))
                            .rem_euclid(Q as i128) as u64
                    })
                    .collect();
                assert_phase(
                    &phase(
                        coefficients.as_ref(),
                        client.accumulator_ntru_secret_key().as_slice(),
                    ),
                    &expected,
                );
            }
            let (_, allocation) = allocations::measure(|| {
                primus_ntru::NlevCiphertext::new(nlev_rows)
                    .write_fourier_form(&mut transformed_nlev, &mut fft);
                transformed_nlev.external_product_to(
                    &public,
                    &mut selected,
                    evaluator.parameters().output_basis(),
                    &mut fft,
                    &mut ep,
                );
                accumulator.decrypt_to(&selected, &mut decoded);
            });
            assert_eq!(allocation.count, 0);
            assert_eq!(decoded, vec![3 * bit; N]);
            let (_, allocation) = allocations::measure(|| {
                control.cmux_to(
                    &choices[0],
                    &choices[1],
                    &mut selected,
                    evaluator.parameters().output_basis(),
                    &mut fft,
                    &mut ep,
                );
                accumulator.decrypt_to(&selected, &mut decoded);
            });
            assert_eq!(allocation.count, 0);
            assert_eq!(decoded, vec![if bit == 0 { 1 } else { 3 }; N]);
        }
    }
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let invalid = primus_tfhe::LweCiphertext::zero(3);
    let nlev_len = nlev.len();
    let ngsw_len = ngsw.len();
    for case in 0..3 {
        nlev.fill(7);
        ngsw.fill(Complex64::new(7.0, 0.0));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.one_hot_to(
                    if case == 0 { &invalid } else { &input },
                    &mut nlev[..if case == 1 { nlev_len - 1 } else { nlev_len }],
                    &mut ngsw[..if case == 2 { ngsw_len - 1 } else { ngsw_len }],
                );
            }))
            .is_err()
        );
        assert!(nlev.iter().all(|&v| v == 7));
        assert!(ngsw.iter().all(|&v| v == Complex64::new(7.0, 0.0)));
    }
    // Compact mode validates its own exact shape before writing. A full batch
    // is oversized here; accepting it would silently change the slot mapping.
    for (input, output_len) in [
        (&invalid, nonzero_ngsw.len()),
        (&input, nonzero_ngsw.len() - 1),
        (&input, ngsw.len()),
        (&input, 0),
    ] {
        ngsw.fill(Complex64::new(7.0, 0.0));
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.one_hot_nonzero_ngsw_to(input, &mut ngsw[..output_len]);
            }))
            .is_err()
        );
        assert!(ngsw.iter().all(|&v| v == Complex64::new(7.0, 0.0)));
    }
    // Recovery and rebinding preserve the PBS/ordinary-CBS workflow.
    let mut ordinary =
        CircuitBootstrapEvaluator::try_from_bootstrapper(evaluator.into_bootstrapper()).unwrap();
    let mut control = ordinary.allocate_output();
    ordinary.circuit_bootstrap_to(&input, &mut control);
    ordinary.cmux_to(&control, &choices[0], &choices[1], &mut selected);
    accumulator.decrypt_to(&selected, &mut decoded);
    assert_eq!(decoded, vec![3; N]);
    let mut evaluator =
        OneHotCircuitBootstrapEvaluator::try_from_bootstrapper(ordinary.into_bootstrapper())
            .unwrap();
    evaluator.one_hot_to(&input, &mut nlev, &mut ngsw);
}

#[test]
fn one_hot_selectors_preserve_gadget_scales_and_control_cmux_without_allocations() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        selectors::<RustFftTable>(distr);
        selectors::<TfheFftTable>(distr);
    }
}
