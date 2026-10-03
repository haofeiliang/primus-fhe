use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_lwe::LweParametersInner;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::NlevParameters;
use primus_ntru::{
    NtruCiphertext, NtruParameters, NttNgswCiphertext, NttNtruExternalProductWorkspace,
    SecretKeyDistr,
};
use primus_ntt::U64NttTable;
use primus_poly::PolyLength;
use primus_test_allocations as allocations;
use primus_tfhe::ProgrammableBootstrap as _;
use primus_tfhe_ntru_ntt::{
    CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig,
    OneHotCircuitBootstrapEvaluator, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
// N=64 leaves guard slots around three interleaved gadget levels at t=8.
const N: usize = 64;
const Q: u128 = 1_125_899_906_826_241;
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
            distance.min(Q - distance) < 1 << 24,
            "actual={actual}, expected={expected}"
        );
    }
}

fn selectors(distr: SecretKeyDistr) {
    let modulus = BarrettModulus::new(Q as u64);
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(10),
        level_count: None,
    };
    let ring = NtruParameters::new(N, 2 * M as u64, modulus, SecretKeyDistr::SparseTernary, 0.7);
    let blind_rotation_basis = ApproxSignedBasis::new(
        ring.cipher_modulus_value(),
        DecompositionBaseLog::new(10),
        None,
    );
    let tfhe = TfheParameters::try_new(
        LweParametersInner::new(
            LweDimension::new(4),
            PowOf2Modulus::new(1u64 << 24),
            distr,
            0.7,
        ),
        NlevParameters::try_with_basis(&ring, blind_rotation_basis).unwrap(),
        full,
        0.7,
    )
    .unwrap();
    let context = TfheContext::<_, U64NttTable, _>::try_from_parameters(tfhe).unwrap();
    let input_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4f48434253);
    let (client, server) = context
        .try_generate_keys(
            Some(CircuitBootstrapConfig {
                output: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: Some(DecompositionLevelCount::new(L)),
                },
                trace: full,
                trace_noise_standard_deviation: 0.7,
                scheme_switch: full,
                scheme_switch_noise_standard_deviation: 0.7,
            }),
            &mut rng,
        )
        .unwrap();
    let mut evaluator =
        OneHotCircuitBootstrapEvaluator::try_new(&context, &server, &input_codec).unwrap();
    assert!(evaluator.bootstrapper_mut().is_none());
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
    let mut joint_nonzero_ngsw = nonzero_ngsw.clone();
    let mut joint_nlev = nlev.clone();
    let selector_len = L * N;
    assert_eq!(evaluator.ngsw_selector_len(), selector_len);
    assert_eq!(evaluator.ngsw_batch_len(), M * selector_len);
    assert_eq!(ngsw.len(), evaluator.ngsw_batch_len());
    assert_eq!(nonzero_ngsw.len(), (M - 1) * selector_len);
    let mut coefficients = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut ep = NttNtruExternalProductWorkspace::new(PolyLength::new(N));

    let encryptor = context.encryptor(&client, &input_codec).unwrap();
    let identity = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap()
        .compile_fn(|m| m as u64)
        .unwrap();
    let mut lwe_output = primus_tfhe::LweCiphertext::zero(4);
    let mut accumulator = context
        .accumulator_client(
            &client,
            ScaledCodec::new(
                input_codec.plaintext_modulus(),
                context.parameters().accumulator_ntru().cipher_modulus(),
            ),
        )
        .unwrap();
    let choices = [1, 3].map(|m| {
        let mut c = context.allocate_accumulator_ciphertext();
        accumulator.encrypt_to(&[m; N], &mut c, &mut rng);
        c
    });
    let mut transformed_nlev = primus_ntru::NttNlevCiphertext::<Vec<_>>::zero(L * N);
    let public = primus_poly::Polynomial::new(vec![(3 * Q / (2 * M) as u128) as u64; N]);
    let mut decoded = vec![0; N];
    // Descending inputs force every selector to overwrite previous nonzero rows.
    for message in (0..M).rev() {
        let input = encryptor.encrypt_padded(message as u64, &mut rng).unwrap();
        if message == M - 1 {
            // Standalone one-hot uses no return storage; recovering ordinary PBS
            // allocates it explicitly. Subsequent alternation retains that PBS.
            let (_, allocation) = allocations::measure(|| {
                evaluator.one_hot_to(input.as_view(), &mut nlev, &mut ngsw);
            });
            assert_eq!(allocation.count, 0);
            let (pbs, allocation) = allocations::measure(|| evaluator.into_bootstrapper());
            assert!(allocation.count > 0);
            evaluator =
                OneHotCircuitBootstrapEvaluator::try_from_bootstrapper(pbs, &input_codec).unwrap();
        }
        let (_, allocation) = allocations::measure(|| {
            evaluator.one_hot_to(input.as_view(), &mut nlev, &mut ngsw);
            evaluator.bootstrapper_mut().unwrap().apply_lookup_table_to(
                input.as_view(),
                &identity,
                lwe_output.as_mut_view(),
            );
            evaluator.one_hot_nlev_to(input.as_view(), &mut nlev_only);
            evaluator.one_hot_ngsw_to(input.as_view(), &mut ngsw_only);
            evaluator.one_hot_nonzero_ngsw_to(input.as_view(), &mut nonzero_ngsw);
            evaluator.one_hot_nlev_and_nonzero_ngsw_to(
                input.as_view(),
                &mut joint_nlev,
                &mut joint_nonzero_ngsw,
            );
        });
        assert_eq!(allocation.count, 0);
        assert_eq!(nlev, nlev_only);
        assert_eq!(ngsw, ngsw_only);
        // Compact slot r - 1 must preserve the full-mode selector r, including
        // the all-zero target bits for message 0 and repeated workspace reuse.
        assert_eq!(nonzero_ngsw, ngsw[selector_len..]);
        // Joint generation reuses projections, preserving both representations.
        assert_eq!(joint_nlev, nlev);
        assert_eq!(joint_nonzero_ngsw, nonzero_ngsw);
        assert_eq!(
            context
                .decryptor(&client, &input_codec)
                .unwrap()
                .decrypt(lwe_output.as_view())
                .unwrap(),
            message as u64
        );
        for selector in 0..M {
            let bit = u64::from(selector == message);
            let nlev_rows = &nlev[selector * L * N..(selector + 1) * L * N];
            let ngsw_len = L * N;
            let control =
                NttNgswCiphertext::new(&ngsw[selector * ngsw_len..(selector + 1) * ngsw_len]);
            for (level, row) in nlev_rows.as_chunks::<N>().0.iter().enumerate() {
                let mut expected = vec![0; N];
                expected[0] = scalars[level] * bit;
                assert_phase(
                    &phase(row, client.accumulator_ntru_secret_key().as_slice()),
                    &expected,
                );
            }
            for (level, row) in control.as_ref().as_chunks::<N>().0.iter().enumerate() {
                primus_ntru::NttNtruCiphertext::new(row)
                    .write_coeff_form(&mut coefficients, context.table());
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
                    .write_ntt_form(&mut transformed_nlev, context.table());
                transformed_nlev.external_product_to(
                    &public,
                    &mut selected,
                    evaluator.parameters().output_basis(),
                    modulus,
                    context.table(),
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
                    modulus,
                    context.table(),
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
    // Both joint layouts reject bad shapes before touching either output.
    for compact in [false, true] {
        let ngsw_len = if compact {
            nonzero_ngsw.len()
        } else {
            ngsw.len()
        };
        for case in 0..3 {
            nlev.fill(7);
            ngsw.fill(7);
            assert!(
                catch_unwind(AssertUnwindSafe(|| {
                    let input = if case == 0 { &invalid } else { &input };
                    let nlev_output = &mut nlev[..if case == 1 { nlev_len - 1 } else { nlev_len }];
                    let ngsw_output = &mut ngsw[..if case == 2 { ngsw_len - 1 } else { ngsw_len }];
                    if compact {
                        evaluator.one_hot_nlev_and_nonzero_ngsw_to(
                            input.as_view(),
                            nlev_output,
                            ngsw_output,
                        );
                    } else {
                        evaluator.one_hot_to(input.as_view(), nlev_output, ngsw_output);
                    }
                }))
                .is_err()
            );
            assert!(nlev.iter().all(|&v| v == 7));
            assert!(ngsw.iter().all(|&v| v == 7));
        }
    }
    // Compact mode validates its own exact shape before writing. A full batch
    // is oversized here; accepting it would silently change the slot mapping.
    for (input, output_len) in [
        (&invalid, nonzero_ngsw.len()),
        (&input, nonzero_ngsw.len() - 1),
        (&input, ngsw.len()),
        (&input, 0),
    ] {
        ngsw.fill(7);
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                evaluator.one_hot_nonzero_ngsw_to(input.as_view(), &mut ngsw[..output_len]);
            }))
            .is_err()
        );
        assert!(ngsw.iter().all(|&v| v == 7));
    }
    // Recovery and rebinding preserve the PBS/ordinary-CBS workflow.
    let (pbs, allocation) = allocations::measure(|| evaluator.into_bootstrapper());
    assert_eq!(allocation.count, 0);
    let mut ordinary = CircuitBootstrapEvaluator::try_from_bootstrapper(pbs, &input_codec).unwrap();
    let mut control = ordinary.allocate_output();
    ordinary.circuit_bootstrap_to(input.as_view(), &mut control);
    ordinary.cmux_to(&control, &choices[0], &choices[1], &mut selected);
    accumulator.decrypt_to(&selected, &mut decoded);
    assert_eq!(decoded, vec![3; N]);
    let mut evaluator = OneHotCircuitBootstrapEvaluator::try_from_bootstrapper(
        ordinary.into_bootstrapper(),
        &input_codec,
    )
    .unwrap();
    evaluator.one_hot_to(input.as_view(), &mut nlev, &mut ngsw);
}

#[test]
fn one_hot_selectors_preserve_gadget_scales_and_control_cmux_without_allocations() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        selectors(distr);
    }
}
