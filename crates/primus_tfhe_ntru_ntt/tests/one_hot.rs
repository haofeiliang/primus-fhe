use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::{NtruCiphertext, NttNtruExternalProductWorkspace, SecretKeyDistr};
use primus_ntt::U64NttTable;
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, CbsGadgetConfig, CircuitBootstrapEvaluator, DecompositionConfig,
    GadgetEncryptionConfig, OneHotCircuitBootstrapEvaluator, PbsParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

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
    let tfhe = PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
        external_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: (PowOf2Modulus::new(1u64 << 24)).into(),
            secret_key_distr: distr,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: modulus.into(),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
        algorithm: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(8),
    })
    .unwrap();
    let blind_rotation = if sparse {
        BlindRotationMethod::Sparse {
            copy_count: 3,
            bucket_count: 8,
        }
    } else {
        BlindRotationMethod::Classic
    };
    let tfhe = tfhe.with_algorithm(blind_rotation);
    let context_parameters = &tfhe;
    let context =
        TfheContext::<_, U64NttTable, _>::try_from_parameters(context_parameters.clone()).unwrap();
    let input_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4f48434253);
    let cbs_config = CbsGadgetConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(L)),
        },
        trace: full,
        scheme_switch: full,
    };
    let context = context.try_with_circuit_bootstrap(cbs_config).unwrap();
    let mut generator = primus_tfhe_ntru_ntt::KeyGenerator::new(&context);
    let (client, server) = generator
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    let (server, circuit) = server.into_parts();
    let (br, return_key) = server.into_parts();
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
    let mut pbs = primus_tfhe_ntru_ntt::Evaluator::try_from_resources(
        resources,
        context_parameters.key_switching(),
        &return_key,
    )
    .unwrap();
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
    // Views distinguish branch numbers from compact slots and reject partial
    // blocks before semantic iterators could silently discard a tail.
    let full = evaluator.ngsw_selectors(&ngsw);
    let nonzero = evaluator.nonzero_ngsw_selectors(&nonzero_ngsw);
    let coefficient = evaluator.nlev_selectors(&nlev);
    assert_eq!(full.selector_range(), 0..M);
    assert_eq!(nonzero.selector_range(), 1..M);
    assert_eq!(full.selector_count(), M);
    assert_eq!(nonzero.selector_count(), M - 1);
    assert_eq!(full.selector_len(), selector_len);
    assert_eq!(coefficient.selector_range(), 0..M);
    assert_eq!(coefficient.selector_count(), M);
    assert_eq!(coefficient.selector_len(), L * N);
    assert!(full.selector(M).is_none());
    assert!(nonzero.selector(0).is_none());
    assert!(nonzero.selector(usize::MAX).is_none());
    assert!(coefficient.selector(M).is_none());
    // Iterators borrow the output, so a temporary metadata view is sufficient.
    {
        let full_iter = evaluator.ngsw_selectors(&ngsw).iter();
        let compact_iter = evaluator.nonzero_ngsw_selectors(&nonzero_ngsw).iter();
        let coefficient_iter = evaluator.nlev_selectors(&nlev).iter();
        assert_eq!(full_iter.len(), M);
        assert_eq!(compact_iter.len(), M - 1);
        assert_eq!(coefficient_iter.len(), M);
    }
    for (r, _) in nonzero.iter() {
        assert!((1..M).contains(&r));
    }
    for malformed in [&ngsw[..ngsw.len() - 1], &nonzero_ngsw[..]] {
        assert!(catch_unwind(AssertUnwindSafe(|| evaluator.ngsw_selectors(malformed))).is_err());
    }
    assert!(catch_unwind(AssertUnwindSafe(|| evaluator.nonzero_ngsw_selectors(&ngsw))).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(
            || evaluator.nlev_selectors(&nlev[..nlev.len() - 1])
        ))
        .is_err()
    );
    let mut coefficients = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut ep = NttNtruExternalProductWorkspace::new(PolyLength::new(N));

    let encryptor = context
        .encryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap();
    let codecs = context
        .parameters()
        .pbs_codecs(PbsMessageConfig::new(input_codec.plaintext_modulus()))
        .unwrap();
    let identity = context
        .parameters()
        .lookup_table_compiler(&codecs)
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
            assert_eq!(next, 2);
        }

        assert_eq!(
            context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .decrypt(lwe_output.as_view())
                .unwrap(),
            message as u64
        );
        let controls = evaluator.ngsw_selectors(&ngsw);
        let compact_controls = evaluator.nonzero_ngsw_selectors(&nonzero_ngsw);
        for (selector, nlev_control) in evaluator.nlev_selectors(&nlev).iter() {
            let bit = u64::from(selector == message);
            let nlev_rows = nlev_control.as_ref();
            let control = controls.selector(selector).unwrap();
            if selector != 0 {
                assert_eq!(
                    compact_controls.selector(selector).unwrap().as_ref(),
                    control.as_ref()
                );
            }
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
            assert_eq!(decoded, vec![3 * bit; N]);
            // Consume r=0 from the full batch and r>0 from the compact one.
            let control = if selector == 0 {
                control
            } else {
                compact_controls.selector(selector).unwrap()
            };
            evaluator.cmux_to(
                &control,
                &choices[0],
                &choices[1],
                &mut selected,
                pbs.bootstrap_resources_mut(),
            );
            accumulator.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, vec![if bit == 0 { 1 } else { 3 }; N]);
            evaluator.external_product_to(
                &control,
                &choices[1],
                &mut selected,
                pbs.bootstrap_resources_mut(),
            );
            accumulator.decrypt_to(&selected, &mut decoded);
            assert_eq!(decoded, vec![3 * bit; N]);
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
    // A whole batch wrapped as one control must be rejected before output writes.
    let batch_control = primus_ntru::NttNgswCiphertext::new(ngsw.as_slice());
    selected.as_mut().fill(7);
    for cmux in [true, false] {
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                if cmux {
                    evaluator.cmux_to(
                        &batch_control,
                        &choices[0],
                        &choices[1],
                        &mut selected,
                        pbs.bootstrap_resources_mut(),
                    );
                } else {
                    evaluator.external_product_to(
                        &batch_control,
                        &choices[1],
                        &mut selected,
                        pbs.bootstrap_resources_mut(),
                    );
                }
            }))
            .is_err()
        );
        assert!(selected.as_ref().iter().all(|&value| value == 7));
    }
    // Circuit operations borrow the same resources; no owning conversion is needed.
    let mut ordinary =
        CircuitBootstrapEvaluator::try_new(pbs.bootstrap_resources(), &circuit, &input_codec)
            .unwrap();
    let mut control = ordinary.allocate_output();
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
    accumulator.decrypt_to(&selected, &mut decoded);
    assert_eq!(decoded, vec![3; N]);
}

#[test]
fn one_hot_selectors_preserve_gadget_scales_and_control_cmux() {
    for (distr, sparse) in [
        (SecretKeyDistr::UniformBinary, false),
        (SecretKeyDistr::UniformTernary, false),
        (SecretKeyDistr::fixed_hamming_weight_binary(4, 2), true),
    ] {
        selectors(distr, sparse);
    }
}
