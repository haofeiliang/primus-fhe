use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_lattice::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_modulus::PowOf2Modulus;
use primus_ntru::NlevParameters;
use primus_ntru::{
    FourierNgswCiphertext, FourierNtruExternalProductWorkspace, NtruCiphertext, NtruParameters,
    SecretKeyDistr,
};
use primus_poly::PolyLength;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_fourier::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig,
    GadgetEncryptionConfig, LweReturnEvaluator, OneHotCircuitBootstrapEvaluator, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
// N=64 leaves guard slots around three interleaved gadget levels at t=8.
const N: usize = 64;
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

fn selectors<Table: FftTable>(distr: SecretKeyDistr, sparse: bool) {
    let modulus = primus_modulus::NativeModulus::<u64>::new();
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
        GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
    )
    .unwrap();
    let context = TfheContext::<_, Table, _>::from_parameters(tfhe);
    let input_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x4f48434253);
    let cbs_config = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(L)),
        },
        trace: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
        scheme_switch: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
    };
    let mut generator = primus_tfhe_ntru_fourier::KeyGenerator::new(&context);
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
        primus_tfhe_ntru_fourier::Evaluator::try_from_resources(resources, &return_key).unwrap()
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
    let selector_len = L * (N / 2);
    assert_eq!(evaluator.ngsw_selector_len(), selector_len);
    assert_eq!(evaluator.ngsw_batch_len(), M * selector_len);
    assert_eq!(ngsw.len(), evaluator.ngsw_batch_len());
    assert_eq!(nonzero_ngsw.len(), (M - 1) * selector_len);
    let mut coefficients = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut selected = NtruCiphertext::<Vec<u64>>::zero(N);
    let mut ep = FourierNtruExternalProductWorkspace::new(PolyLength::new(N));
    let mut fft = context.new_fft_engine();
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
    let mut transformed_nlev = primus_ntru::FourierNlevCiphertext::<Vec<_>>::zero(L * (N / 2));
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
            ngsw.fill(Complex64::new(7.0, 0.0));
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
            assert!(ngsw.iter().all(|&v| v == Complex64::new(7.0, 0.0)));
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
        ngsw.fill(Complex64::new(7.0, 0.0));
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
        assert!(ngsw.iter().all(|&v| v == Complex64::new(7.0, 0.0)));
    }

    check_return_batches(
        &mut evaluator,
        &return_key,
        &choices,
        &input,
        &mut ngsw,
        &mut pbs,
    );

    // Ordinary CBS, one-hot and PBS borrow the same common FFT/EP owner.
    let mut ordinary =
        CircuitBootstrapEvaluator::try_new(pbs.bootstrap_resources(), &circuit, &input_codec)
            .unwrap();
    let mut control = ordinary.allocate_output();
    let (_, allocation) = allocations::measure(|| {
        pbs.apply_lookup_table_to(input.as_view(), &identity, lwe_output.as_mut_view());
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

// Compare every streamed sample with the scalar return oracle, then check that
// the independent return buffers stay live while one-hot and ordinary PBS run.
fn check_return_batches<'a, Table: FftTable>(
    evaluator: &mut OneHotCircuitBootstrapEvaluator<'a, u64, Table, PowOf2Modulus<u64>>,
    return_key: &primus_ntru::NtruLweKeySwitchingKey<u64>,
    choices: &[NtruCiphertext<Vec<u64>>],
    input: &primus_tfhe::LweCiphertext<u64>,
    ngsw: &mut [Complex64],
    pbs: &mut primus_tfhe_ntru_fourier::Evaluator<'a, u64, Table, PowOf2Modulus<u64>>,
) {
    let context = pbs.bootstrap_resources().context();
    let input_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());
    // The allocation-free binding rejects a different target q before workspace setup.
    assert_rejected(|| {
        let _ = LweReturnEvaluator::new(return_key, PowOf2Modulus::new(1u64 << 23));
    });
    let (lwe_return, allocation) = allocations::measure(|| {
        LweReturnEvaluator::new(
            return_key,
            context.parameters().external_lwe().cipher_modulus(),
        )
    });
    assert_eq!(allocation.count, 0);
    let mut scalar_workspace = lwe_return.new_scalar_workspace();
    let mut batch_workspace = lwe_return.new_batch_workspace();
    let capacity = batch_workspace.batch_capacity();
    let indices = [0, N / 2, N - 1];
    let mut expected = (0..capacity)
        .map(|_| context.allocate_lwe_ciphertext())
        .collect::<Vec<_>>();
    let mut scalar_return = primus_ntru::NtruLweKeySwitchingWorkspace::new(PolyLength::new(N));
    for (i, output) in expected.iter_mut().enumerate() {
        return_key.key_switch_at_to(
            &choices[i % choices.len()],
            indices[i % indices.len()],
            output,
            context.parameters().external_lwe().cipher_modulus(),
            &mut scalar_return,
        );
    }
    let mut returned = expected.clone();
    for output in &mut returned {
        output.as_mut().fill(7);
    }
    let untouched = returned.clone();

    // Neither inactive storage nor a freshly started empty prefix is a sample.
    assert_rejected(|| lwe_return.return_batch_to(&mut returned, &mut batch_workspace));
    assert_rejected(|| lwe_return.append_at(choices[0].as_view(), 0, &mut batch_workspace));
    batch_workspace.begin_batch();
    assert_rejected(|| lwe_return.return_batch_to(&mut returned, &mut batch_workspace));
    assert_eq!(returned, untouched);
    lwe_return.return_batch_to(&mut [], &mut batch_workspace);

    // Fill a full tile in order. One-hot can reuse BR/FFT between appends without
    // changing the return prefix; only ciphertext samples survive each append.
    let (_, allocation) = allocations::measure(|| {
        batch_workspace.begin_batch();
        for i in 0..capacity {
            lwe_return.append_at(
                choices[i % choices.len()].as_view(),
                indices[i % indices.len()],
                &mut batch_workspace,
            );
            if i == 0 {
                evaluator.one_hot_ngsw_to(input.as_view(), ngsw, pbs.bootstrap_resources_mut());
            }
        }
    });
    assert_eq!(allocation.count, 0);
    assert_rejected(|| lwe_return.append_at(choices[0].as_view(), 0, &mut batch_workspace));
    assert_rejected(|| {
        lwe_return.return_batch_to(&mut returned[..capacity - 1], &mut batch_workspace)
    });
    assert_eq!(returned, untouched);

    // Reject every output dimension before writing the first valid output.
    let last = returned.pop().unwrap();
    returned.push(primus_tfhe::LweCiphertext::zero(1));
    let malformed = returned.clone();
    assert_rejected(|| lwe_return.return_batch_to(&mut returned, &mut batch_workspace));
    assert_eq!(returned, malformed);
    *returned.last_mut().unwrap() = last;

    // Shared-input return cannot overwrite an active batch. Scalar scratch is
    // independent: using it while a batch is pending preserves every filled slot.
    let mut scalar_output = context.allocate_lwe_ciphertext();
    let (_, allocation) = allocations::measure(|| {
        lwe_return.return_at_to(
            choices[0].as_view(),
            0,
            scalar_output.as_mut_view(),
            &mut scalar_workspace,
        );
    });
    assert_eq!(allocation.count, 0);
    assert_eq!(scalar_output, expected[0]);
    assert_rejected(|| {
        lwe_return.return_prefix_to(
            choices[0].as_view(),
            &mut returned[..2],
            &mut batch_workspace,
        )
    });
    assert_eq!(returned, untouched);
    let identity = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap()
        .compile_fn(|m| m as u64)
        .unwrap();
    let many = context
        .parameters()
        .lookup_table_compiler(&input_codec)
        .unwrap()
        .compile_interleaved_fn(2, |m, _| m as u64)
        .unwrap();
    let (_, allocation) = allocations::measure(|| {
        pbs.apply_lookup_table_to(input.as_view(), &identity, returned[0].as_mut_view());
        pbs.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut returned[..2]);
    });
    assert_eq!(allocation.count, 0);
    let (_, allocation) =
        allocations::measure(|| lwe_return.return_batch_to(&mut returned, &mut batch_workspace));
    assert_eq!(allocation.count, 0);
    assert_eq!(returned, expected);
    assert_rejected(|| lwe_return.return_batch_to(&mut returned, &mut batch_workspace));
    assert_eq!(returned, expected);

    // Restart invalidates the old prefix, then a singleton overwrites only its
    // output. Invalid source/index appends do not advance the new prefix.
    batch_workspace.begin_batch();
    lwe_return.append_at(choices[0].as_view(), 0, &mut batch_workspace);
    batch_workspace.begin_batch();
    assert_rejected(|| lwe_return.return_batch_to(&mut returned[..1], &mut batch_workspace));
    assert_rejected(|| {
        lwe_return.append_at(NtruCiphertext::new(&[0u64][..]), 0, &mut batch_workspace)
    });
    assert_rejected(|| lwe_return.append_at(choices[0].as_view(), N, &mut batch_workspace));
    lwe_return.append_at(choices[1].as_view(), indices[1], &mut batch_workspace);
    lwe_return.return_batch_to(&mut returned[..1], &mut batch_workspace);
    assert_eq!(returned[0], expected[1]);
    assert_eq!(returned[1..], expected[1..]);

    // Discard ends the stream; shared-input return can reuse the batch buffers.
    batch_workspace.begin_batch();
    lwe_return.append_at(choices[0].as_view(), 0, &mut batch_workspace);
    batch_workspace.discard_batch();
    let (_, allocation) = allocations::measure(|| {
        lwe_return.return_at_to(
            choices[0].as_view(),
            indices[0],
            returned[0].as_mut_view(),
            &mut scalar_workspace,
        );
        lwe_return.return_prefix_to(
            choices[0].as_view(),
            &mut returned[..2],
            &mut batch_workspace,
        );
    });
    assert_eq!(allocation.count, 0);
    for (index, output) in returned[..2].iter().enumerate() {
        let mut expected = context.allocate_lwe_ciphertext();
        return_key.key_switch_at_to(
            &choices[0],
            index,
            &mut expected,
            context.parameters().external_lwe().cipher_modulus(),
            &mut scalar_return,
        );
        assert_eq!(output, &expected);
    }
}

fn assert_rejected(operation: impl FnOnce()) {
    assert!(catch_unwind(AssertUnwindSafe(operation)).is_err());
}

#[test]
fn one_hot_selectors_preserve_gadget_scales_and_control_cmux_without_allocations() {
    for (distr, sparse) in [
        (SecretKeyDistr::UniformBinary, false),
        (SecretKeyDistr::UniformTernary, false),
        (SecretKeyDistr::fixed_hamming_weight_binary(4, 2), true),
    ] {
        selectors::<RustFftTable>(distr, sparse);
        selectors::<TfheFftTable>(distr, sparse);
    }
}
