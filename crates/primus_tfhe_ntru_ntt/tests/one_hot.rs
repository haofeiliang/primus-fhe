use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::NlevParameters;
use primus_ntru::{
    NtruCiphertext, NtruParameters, NttNgswCiphertext, NttNtruExternalProductWorkspace,
    SecretKeyDistr,
};
use primus_ntt::U64NttTable;
use primus_poly::PolyLength;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_ntt::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig,
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

fn selectors(distr: SecretKeyDistr, sparse: bool) {
    let modulus = BarrettModulus::new(Q as u64);
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(10),
        level_count: None,
    };
    let ring = NtruParameters::new(
        PolyLength::new(N),
        2 * M as u64,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let blind_rotation_basis = ApproxSignedBasis::new(
        ring.cipher_modulus_value(),
        DecompositionBaseLog::new(10),
        None,
    );
    let tfhe = TfheParameters::try_new(
        LweEncryptionParameters::new(
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
    let cbs_config = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(L)),
        },
        trace: full,
        trace_noise_standard_deviation: 0.7,
        scheme_switch: full,
        scheme_switch_noise_standard_deviation: 0.7,
    };
    let mut generator = primus_tfhe_ntru_ntt::KeyGenerator::new(&context);
    let client = generator.try_generate_client_key(&mut rng).unwrap();
    let blind_rotation = if sparse {
        BlindRotationConfig::Sparse {
            copy_count: 3,
            bucket_count: 8,
        }
    } else {
        BlindRotationConfig::Classic
    };
    let server = generator
        .try_generate_server_key(&client, blind_rotation, Some(cbs_config), &mut rng)
        .unwrap();
    let ((br, return_key, circuit), allocation) = allocations::measure(|| server.into_parts());
    assert_eq!(allocation.count, 0);
    let circuit = circuit.unwrap();
    // One-hot preparation depends on the context/CBS key, not on BR controls.
    // In the sparse case prepare using a classic BR over the same two secrets,
    // then lend sparse resources for every numerical check below.
    let classic_br = if sparse {
        Some(
            generator
                .try_generate_classic_blind_rotation_key(&client, &mut rng)
                .unwrap(),
        )
    } else {
        None
    };
    let resources = context
        .bootstrap_resources(classic_br.as_ref().unwrap_or(&br))
        .unwrap();
    let mut evaluator =
        OneHotCircuitBootstrapEvaluator::try_new(&resources, &circuit, &input_codec).unwrap();
    let resources = if sparse {
        context.bootstrap_resources(&br).unwrap()
    } else {
        resources
    };
    let (mut pbs, allocation) = allocations::measure(|| {
        primus_tfhe_ntru_ntt::Evaluator::try_from_resources(resources, &return_key).unwrap()
    });
    assert!(allocation.count > 0);
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
    let mut pair = evaluator.new_sparse_pair_workspace(pbs.bootstrap_resources_mut());
    assert_eq!(pair.is_some(), sparse);
    let mut paired_nlev = nlev.clone();
    let mut paired_ngsw = nonzero_ngsw.clone();
    let selector_len = L * N;
    assert_eq!(evaluator.ngsw_selector_len(), selector_len);
    assert_eq!(evaluator.ngsw_batch_len(), M * selector_len);
    assert_eq!(ngsw.len(), evaluator.ngsw_batch_len());
    assert_eq!(nonzero_ngsw.len(), (M - 1) * selector_len);
    let mut coefficients = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut ep = NttNtruExternalProductWorkspace::new(PolyLength::new(N));

    let encryptor = context
        .encryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let identity = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap()
        .compile_fn(|m| m as u64)
        .unwrap();
    let mut lwe_output = primus_tfhe::LweCiphertext::zero(4);
    let mut accumulator = context
        .accumulator_client(
            client.accumulator_ntru_secret_key(),
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
    // Keep an independent second input and its serial oracle. Repeated pairs
    // must preserve input order while reusing the same projection destinations.
    let second_input = encryptor.encrypt_padded(2, &mut rng).unwrap();
    let mut second_nlev = nlev.clone();
    let mut second_ngsw = nonzero_ngsw.clone();
    evaluator.one_hot_nlev_and_nonzero_ngsw_to(
        second_input.as_view(),
        &mut second_nlev,
        &mut second_ngsw,
        pbs.bootstrap_resources_mut(),
    );
    // Descending inputs overwrite nonzero rows. Exact quantized guard endpoints
    // isolate the packed LUT convention from fresh-encryption randomness.
    let a = evaluator.lookup_table().guard_radius() as i64;
    let cases = (0..M)
        .rev()
        .map(|message| (message, None))
        .chain([(0, Some(-a)), (M - 1, Some(a - 1))]);
    for (message, error) in cases {
        let mut input = encryptor.encrypt_padded(message as u64, &mut rng).unwrap();
        if let Some(error) = error {
            let lut = evaluator.lookup_table();
            let exponent = (message as i64 * lut.selector_stride() as i64
                + error * lut.rotation_step() as i64)
                .rem_euclid(2 * N as i64) as u64;
            input.a_mut().fill(0);
            *input.b_mut() = exponent * ((1u64 << 24) / (2 * N as u64));
        }
        let (_, allocation) = allocations::measure(|| {
            evaluator.one_hot_to(
                input.as_view(),
                &mut nlev,
                &mut ngsw,
                pbs.bootstrap_resources_mut(),
            );
            pbs.apply_lookup_table_to(input.as_view(), &identity, lwe_output.as_mut_view());
            evaluator.one_hot_nlev_to(
                input.as_view(),
                &mut nlev_only,
                pbs.bootstrap_resources_mut(),
            );
            evaluator.one_hot_ngsw_to(
                input.as_view(),
                &mut ngsw_only,
                pbs.bootstrap_resources_mut(),
            );
            evaluator.one_hot_nonzero_ngsw_to(
                input.as_view(),
                &mut nonzero_ngsw,
                pbs.bootstrap_resources_mut(),
            );
            evaluator.one_hot_nlev_and_nonzero_ngsw_to(
                input.as_view(),
                &mut joint_nlev,
                &mut joint_nonzero_ngsw,
                pbs.bootstrap_resources_mut(),
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
        if let Some(pair) = pair.as_mut() {
            let mut next = 0;
            let (_, allocation) = allocations::measure(|| {
                evaluator.with_sparse_pair(
                    [input.as_view(), second_input.as_view()],
                    pair,
                    pbs.bootstrap_resources_mut(),
                    |index, projection| {
                        assert_eq!(index, next);
                        next += 1;
                        projection.project_to(Some(&mut paired_nlev), Some(&mut paired_ngsw));
                        let (expected_nlev, expected_ngsw) = if index == 0 {
                            (&nlev, &nonzero_ngsw)
                        } else {
                            (&second_nlev, &second_ngsw)
                        };
                        assert_eq!(&paired_nlev, expected_nlev);
                        assert_eq!(&paired_ngsw, expected_ngsw);
                    },
                );
            });
            assert_eq!(next, 2);
            assert_eq!(allocation.count, 0);
        }

        assert_eq!(
            context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
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
    if let Some(pair) = pair.as_mut() {
        // Invalid second input is rejected before any callback. A later output
        // error can leave the first callback written; the next call must recover.
        let mut calls = 0;
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.with_sparse_pair(
                [input.as_view(), invalid.as_view()],
                pair,
                pbs.bootstrap_resources_mut(),
                |_, _| calls += 1,
            )))
            .is_err()
        );
        assert_eq!(calls, 0);
        assert!(
            catch_unwind(AssertUnwindSafe(|| evaluator.with_sparse_pair(
                [second_input.as_view(), input.as_view()],
                pair,
                pbs.bootstrap_resources_mut(),
                |index, projection| {
                    if index == 0 {
                        projection.project_to(Some(&mut paired_nlev), Some(&mut paired_ngsw));
                    } else {
                        projection.project_to(Some(&mut []), None);
                    }
                },
            )))
            .is_err()
        );
        assert_eq!(paired_nlev, second_nlev);
        evaluator.with_sparse_pair(
            [second_input.as_view(), second_input.as_view()],
            pair,
            pbs.bootstrap_resources_mut(),
            |_, projection| {
                projection.project_to(Some(&mut paired_nlev), Some(&mut paired_ngsw));
                assert_eq!(paired_nlev, second_nlev);
                assert_eq!(paired_ngsw, second_ngsw);
            },
        );
    }
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
                            pbs.bootstrap_resources_mut(),
                        );
                    } else {
                        evaluator.one_hot_to(
                            input.as_view(),
                            nlev_output,
                            ngsw_output,
                            pbs.bootstrap_resources_mut(),
                        );
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
                evaluator.one_hot_nonzero_ngsw_to(
                    input.as_view(),
                    &mut ngsw[..output_len],
                    pbs.bootstrap_resources_mut(),
                );
            }))
            .is_err()
        );
        assert!(ngsw.iter().all(|&v| v == 7));
    }
    // Circuit operations borrow the same resources; no owning conversion is needed.
    let mut ordinary =
        CircuitBootstrapEvaluator::try_new(pbs.bootstrap_resources(), &circuit, &input_codec)
            .unwrap();
    let mut control = ordinary.allocate_output();
    let (_, allocation) = allocations::measure(|| {
        ordinary.circuit_bootstrap_to(input.as_view(), &mut control, pbs.bootstrap_resources_mut());
        ordinary.cmux_to(
            &control,
            &choices[0],
            &choices[1],
            &mut selected,
            pbs.bootstrap_resources_mut(),
        );
        evaluator.one_hot_to(
            input.as_view(),
            &mut nlev,
            &mut ngsw,
            pbs.bootstrap_resources_mut(),
        );
    });
    assert_eq!(allocation.count, 0);
    accumulator.decrypt_to(&selected, &mut decoded);
    assert_eq!(decoded, vec![3; N]);
}

#[test]
fn one_hot_selectors_preserve_gadget_scales_and_control_cmux_without_allocations() {
    for (distr, sparse) in [
        (SecretKeyDistr::UniformBinary, false),
        (SecretKeyDistr::UniformTernary, false),
        (SecretKeyDistr::fixed_hamming_weight_binary(4, 2), true),
    ] {
        selectors(distr, sparse);
    }
}
