//! Gadget-scale phases and actual CMux/external-product consumption;
//! parameter-constructor boundaries belong to the common family crate.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::{NttNgswCiphertext, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::U64NttTable;
use primus_poly::PolyLength;
use primus_poly::Polynomial;
use primus_tfhe::PbsMessageConfig;
use primus_tfhe_ntru_ntt::{
    BlindRotationMethod, CbsGadgetConfig, CbsParameters, CircuitBootstrapEvaluator,
    DecompositionConfig, GadgetEncryptionConfig, PbsParameters, TfheContext,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const N: usize = 64;
const Q: u64 = 1_125_899_906_826_241;

// Reuse one evaluator across controls, then consume its gadget ciphertexts.
fn circuit_bootstrap(distr: SecretKeyDistr, sparse: bool) {
    let modulus = BarrettModulus::new(Q);

    let tfhe = PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
        external_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(16),
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
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        algorithm: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(4),
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
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    // Three gadget levels exercise multiple scales and an internal padding slot.
    let levels = 3;
    let cbs_config = CbsGadgetConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(levels)),
        },
        trace: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: None,
        },
        scheme_switch: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(10),
            level_count: None,
        },
    };
    // The CBS bundle shares one BR/KS server key with subsequent PBS calls.
    let context = context.try_with_circuit_bootstrap(cbs_config).unwrap();
    let mut generator = primus_tfhe_ntru_ntt::KeyGenerator::new(&context);
    let (client, ring_server) = generator
        .try_generate_circuit_bootstrap_keys(&mut rng)
        .unwrap();
    {
        let resources = ring_server.bootstrap_resources(&context).unwrap();
        let _cbs = CircuitBootstrapEvaluator::try_new(
            &resources,
            ring_server.circuit_bootstrap_key(),
            &input_codec,
        )
        .unwrap();
    }
    let server = ring_server;
    let circuit_key = server.circuit_bootstrap_key();
    let parameters = circuit_key.parameters();
    // Classic exposes coordinate controls; sparse owns coefficient buckets.
    if let Some(controls) = server.server_key().blind_rotation_key().classic_controls() {
        assert_eq!(controls.is_binary(), distr.is_binary());
        assert_eq!(controls.first_controls().1.is_none(), distr.is_binary());
        assert_eq!(
            controls.remaining_controls().len(),
            (context.parameters().external_lwe_dimension().get() - 1)
                * if distr.is_binary() { 1 } else { 2 },
        );
    } else {
        assert!(sparse);
    }

    let key = NttNtruSecretKey::try_from_coeff_secret_key(
        client.accumulator_ntru_secret_key(),
        modulus,
        context.table(),
    )
    .unwrap();
    let encryptor = context
        .encryptor(client.external_lwe_secret_key(), &input_codec)
        .unwrap();
    // The same CBS-enabled server key also supports ordinary PBS.
    let codecs = context
        .parameters()
        .pbs_codecs(PbsMessageConfig::new(input_codec.plaintext_modulus()))
        .unwrap();
    let identity = context
        .parameters()
        .lookup_table_compiler(&codecs)
        .unwrap()
        .compile_fn(|message| message as u64)
        .unwrap();
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let mut output = context
        .evaluator(server.server_key())
        .unwrap()
        .apply_lookup_table(input.as_view(), &identity);
    assert_eq!(
        context
            .decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap()
            .decrypt(output.as_view())
            .unwrap(),
        1
    );

    let mut accumulator_client = context
        .accumulator_client(
            client.accumulator_ntru_secret_key(),
            ScaledCodec::new(
                input_codec.plaintext_modulus(),
                context.parameters().accumulator_ntru().cipher_modulus(),
            ),
        )
        .unwrap();
    let choices = [1u64, 3].map(|message| {
        let mut output = context.allocate_accumulator_ciphertext();
        accumulator_client.encrypt_to(&[message; N], &mut output, &mut rng);
        output
    });

    // CBS needs no return scratch. Ordinary PBS can later take ownership of
    // the common resources and allocate only its missing return buffers.
    let mut resources = context
        .bootstrap_resources(server.server_key().blind_rotation_key())
        .unwrap();
    let mut evaluator =
        CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec).unwrap();
    let foreign_input = RoundedCodec::new(4, PowOf2Modulus::new(1u64 << 23));
    let foreign_program = parameters
        .compile_lookup_table_fn(&foreign_input, |_| 0)
        .unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_with_lookup_table(&resources, circuit_key, foreign_program,),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
    let wrong_basis = ApproxSignedBasis::new(
        parameters.output_basis().modulus(),
        DecompositionBaseLog::new(9),
        Some(DecompositionLevelCount::new(3)),
    );
    let wrong_program = primus_tfhe::CircuitBootstrapLookupTable::try_from_fn(
        PolyLength::new(N),
        &input_codec,
        &wrong_basis,
        context.parameters().accumulator_ntru().cipher_modulus(),
        |_| 0,
    )
    .unwrap();
    assert!(matches!(
        CircuitBootstrapEvaluator::try_with_lookup_table(&resources, circuit_key, wrong_program,),
        Err(primus_tfhe::TfheEvaluationError::IncompatibleCircuitBootstrapLookupTable)
    ));
    let mut standalone_control = evaluator.allocate_output();
    evaluator.circuit_bootstrap_to(input.as_view(), &mut standalone_control, &mut resources);
    let mut pbs = primus_tfhe_ntru_ntt::Evaluator::try_from_resources(
        resources,
        context_parameters.key_switching(),
        server.server_key().key_switching_key(),
    )
    .unwrap();
    let mut control = evaluator.allocate_output();
    let mut selected = context.allocate_accumulator_ciphertext();
    let mut product = context.allocate_accumulator_ciphertext();
    let mut decoded = vec![0; N];
    let mut decoded_product = vec![0; N];
    // Client shape failures precede sampling or writes, even with reused storage.
    selected.as_mut().fill(7);
    let mut rejected_rng = StdRng::seed_from_u64(43);
    let mut untouched_rng = StdRng::seed_from_u64(43);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            accumulator_client.encrypt_to(&[0; N - 1], &mut selected, &mut rejected_rng);
        }))
        .is_err()
    );
    assert_eq!(rejected_rng.random::<u64>(), untouched_rng.random::<u64>());
    assert!(selected.as_ref().iter().all(|&value| value == 7));
    decoded.fill(7);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            accumulator_client.decrypt_to(&selected, &mut decoded[..N - 1]);
        }))
        .is_err()
    );
    assert!(decoded.iter().all(|&value| value == 7));
    let short_input = primus_ntru::NtruCiphertext::new(&choices[0].as_ref()[..N - 1]);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.external_product_to(
                &control,
                &short_input,
                &mut selected,
                pbs.bootstrap_resources_mut(),
            );
        }))
        .is_err()
    );
    assert!(selected.as_ref().iter().all(|&value| value == 7));
    // Reuse the same keys with identity, a t=8 predicate, and an integer control.
    // Non-bit outputs are consumed only by the external product.
    for (t, message, value, values) in [
        (4u64, 1u64, 1u64, None),
        (8, 1, 1, None),
        (8, 0, 0, None),
        (8, 3, 1, Some([0, 0, 1, 1].as_slice())),
        (8, 1, 0, Some([0, 0, 1, 1].as_slice())),
        (4, 0, 2, Some([2, 3].as_slice())),
    ] {
        let input_codec =
            RoundedCodec::new(t, context.parameters().external_lwe().cipher_modulus());
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
        evaluator = if let Some(values) = values {
            let program = parameters
                .compile_lookup_table_slice(&input_codec, values)
                .unwrap();
            CircuitBootstrapEvaluator::try_with_lookup_table(
                pbs.bootstrap_resources(),
                circuit_key,
                program,
            )
        } else {
            CircuitBootstrapEvaluator::try_new(pbs.bootstrap_resources(), circuit_key, &input_codec)
        }
        .unwrap();
        let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
        evaluator.circuit_bootstrap_to(
            input.as_view(),
            &mut control,
            pbs.bootstrap_resources_mut(),
        );
        if value <= 1 {
            evaluator.cmux_to(
                &control,
                &choices[0],
                &choices[1],
                &mut selected,
                pbs.bootstrap_resources_mut(),
            );
        }
        evaluator.external_product_to(
            &control,
            &choices[1],
            &mut product,
            pbs.bootstrap_resources_mut(),
        );
        pbs.apply_lookup_table_to(input.as_view(), &identity, output.as_mut_view());
        accumulator_client.decrypt_to(&selected, &mut decoded);
        accumulator_client.decrypt_to(&product, &mut decoded_product);
        assert_eq!(
            context
                .decryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .decrypt(output.as_view())
                .unwrap(),
            message
        );
        let mut phase = Polynomial::new(vec![0u64; N]);
        for (scalar, level) in parameters
            .output_basis()
            .scalar_iter()
            .zip(control.iter_ntt_ntru(N))
        {
            key.decrypt_phase_to(&level, &mut phase, modulus, context.table());
            for (&actual, &f) in phase
                .as_ref()
                .iter()
                .zip(client.accumulator_ntru_secret_key().as_slice())
            {
                let value = (u128::from(scalar) * u128::from(f.unsigned_abs()) * u128::from(value))
                    % u128::from(Q);
                let expected = if f < 0 {
                    (u128::from(Q) - value) % u128::from(Q)
                } else {
                    value
                };
                let distance = (u128::from(actual) + u128::from(Q) - expected) % u128::from(Q);
                // Functional bound, below even the third-layer gadget step.
                assert!(distance.min(u128::from(Q) - distance) < (1 << 24));
            }
        }
        if value <= 1 {
            assert_eq!(decoded, vec![if value == 0 { 1 } else { 3 }; N]);
        }
        assert_eq!(decoded_product, vec![3 * value % 4; N]);
    }
    control.as_mut().fill(7);
    let invalid = primus_tfhe::LweCiphertext::zero(15);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evaluator
            .circuit_bootstrap_to(
                invalid.as_view(),
                &mut control,
                pbs.bootstrap_resources_mut()
            )))
        .is_err()
    );
    assert!(control.as_ref().iter().all(|&value| value == 7));
    // Equal parameters do not authorize swapping the context bound to prepared
    // operation state. Reject the new resource argument before touching output.
    let other_context_parameters = &context.parameters().clone();
    let other_context =
        TfheContext::<_, U64NttTable, _>::try_from_parameters(other_context_parameters.clone())
            .unwrap();
    let mut other_resources = other_context
        .bootstrap_resources(server.server_key().blind_rotation_key())
        .unwrap();
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            evaluator.circuit_bootstrap_to(input.as_view(), &mut control, &mut other_resources);
        }))
        .is_err()
    );
    assert!(control.as_ref().iter().all(|&value| value == 7));
    let input = encryptor.encrypt_padded(1u64, &mut rng).unwrap();
    let short_len = control.as_ref().len() - 1;
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| evaluator
            .circuit_bootstrap_to(
                input.as_view(),
                &mut NttNgswCiphertext::new(&mut control.as_mut()[..short_len]),
                pbs.bootstrap_resources_mut()
            )))
        .is_err()
    );
    assert!(control.as_ref().iter().all(|&value| value == 7));

    // A different compatible key object changes only the binding, not scratch.
    let return_key = server.server_key().key_switching_key().clone();
    pbs.try_rebind_return_key(&return_key).unwrap();
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
    let mut output = context.allocate_lwe_ciphertext();
    pbs.apply_lookup_table_to(input.as_view(), &identity, output.as_mut_view());
    assert_eq!(
        context
            .decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap()
            .decrypt(output.as_view())
            .unwrap(),
        1
    );
}

#[test]
fn circuit_bootstrap_preserves_gadget_scales_and_controls_cmux() {
    for (distr, sparse) in [
        (SecretKeyDistr::UniformBinary, false),
        (SecretKeyDistr::fixed_composition_ternary(16, 3, 4), false),
        (SecretKeyDistr::fixed_hamming_weight_binary(16, 2), true),
    ] {
        circuit_bootstrap(distr, sparse);
    }
}

// Complete CBS bundles include KS and require f to fit return q. Component
// BR/CBS generation still checks only the domains consumed by those components.
#[test]
fn cbs_bundle_requires_return_compatible_secrets() {
    use primus_tfhe_ntru_ntt::{
        CbsGadgetParameters, ClientKey, KeyGenerator, OneHotCircuitBootstrapEvaluator, TfheKeyError,
    };
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    };
    let cbs_config = CbsGadgetConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(4),
            level_count: Some(DecompositionLevelCount::new(1)),
        },
        trace: full,
        scheme_switch: full,
    };
    use primus_tfhe_ntru_ntt::{CbsConfig, LweConfig, ModulusConfig, PbsConfig};
    let config = CbsConfig::<u32, primus_modulus::PowOf2Modulus<u32>> {
        gadget: cbs_config,
        pbs: PbsConfig {
            external_lwe: LweConfig {
                dimension: LweDimension::new(2),
                cipher_modulus: ModulusConfig::Explicit(16u32),
                secret_key_distr: SecretKeyDistr::UniformBinary,
                noise_standard_deviation: 0.7,
            },
            acc_modulus: ModulusConfig::Explicit(65_537u32),
            bsk_poly_length: PolyLength::new(32),
            bsk_secret_distr: SecretKeyDistr::gaussian(3.2),
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: full,
                noise_standard_deviation: 0.7,
            },
            algorithm: BlindRotationMethod::Classic,
            key_switching: GadgetEncryptionConfig {
                decomposition: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(2),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            messages: primus_tfhe::PbsMessageConfig::new(4),
        },
    };
    let return_config = config.pbs.key_switching;
    // Generated keys also need the q bound when the sampler support is wider.
    // Fixed seeds cover both rejection and an accepted sample below that support bound.
    for (q, accepted) in [(16u32, false), (64, true)] {
        let mut candidate = config;
        candidate.pbs.bsk_secret_distr = SecretKeyDistr::gaussian(12.8);
        candidate.pbs.external_lwe.cipher_modulus = ModulusConfig::Explicit(q);
        candidate.pbs.key_switching = return_config;
        let candidate_parameters = &PbsParameters::try_from_config(candidate.pbs).unwrap();
        let candidate = TfheContext::<_, primus_ntt::U32NttTable, _>::try_from_parameters(
            candidate_parameters.clone(),
        )
        .unwrap()
        .try_with_circuit_bootstrap(cbs_config)
        .unwrap();
        let mut generator = KeyGenerator::new(&candidate);
        let mut sample_rng = StdRng::seed_from_u64(42);
        let result = generator.try_generate_circuit_bootstrap_keys(&mut sample_rng);
        let expected_error =
            (!accepted).then_some(primus_tfhe_ntru::KeyGenerationError::ClientKey(
                TfheKeyError::AccumulatorSecretOutsideLweModulus,
            ));
        assert_eq!(result.as_ref().err(), expected_error.as_ref());
        if let Ok((sample, server)) = result {
            assert!(
                sample
                    .accumulator_ntru_secret_key()
                    .as_slice()
                    .iter()
                    .all(|s| s.unsigned_abs() < q)
            );
            let codec =
                RoundedCodec::new(4, candidate.parameters().external_lwe().cipher_modulus());
            let resources = server.bootstrap_resources(&candidate).unwrap();
            CircuitBootstrapEvaluator::try_new(&resources, server.circuit_bootstrap_key(), &codec)
                .unwrap();
            candidate.evaluator(server.server_key()).unwrap();
        }
        // The same sampled secret must satisfy the same return-q contract for PBS.
        let result = generator.try_generate_with_parameters(
            candidate_parameters.key_switching(),
            BlindRotationMethod::Classic,
            &mut StdRng::seed_from_u64(42),
        );
        assert_eq!(result.err(), expected_error);
    }
    let parameters = CbsParameters::try_from_config(config.pbs, config.gadget).unwrap();
    let context_parameters = &parameters;
    let context = TfheContext::<_, primus_ntt::U32NttTable, _>::try_from_cbs_parameters(
        context_parameters.clone(),
    )
    .unwrap();
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let mut f = vec![0; 32];
    f[0] = 17; // Invertible at Q, but not representable as a signed magnitude below q=16.
    let client = ClientKey::new(
        primus_lwe::LweSecretKey::new(
            vec![0, 1],
            SecretKeyDistr::UniformBinary,
            input_codec.ciphertext_modulus(),
        ),
        primus_ntru::NtruSecretKey::new(f, SecretKeyDistr::gaussian(3.2)),
    );
    let mut rng = StdRng::seed_from_u64(0x4342535f4f4e4c59);
    let mut untouched = StdRng::seed_from_u64(0x4342535f4f4e4c59);
    let mut generator = KeyGenerator::new(&context);
    assert_eq!(
        generator
            .try_generate_circuit_bootstrap_server_key(&client, &mut rng)
            .err(),
        Some(primus_tfhe_ntru::KeyGenerationError::ClientKey(
            TfheKeyError::AccumulatorSecretOutsideLweModulus,
        )),
    );
    assert_eq!(rng.random::<u64>(), untouched.random::<u64>());
    let br = generator
        .try_generate_classic_blind_rotation_key(&client, &mut rng)
        .unwrap();
    let cbs_parameters =
        CbsGadgetParameters::try_from_config(context.parameters(), cbs_config).unwrap();
    let (_, accumulator) = client.into_parts();
    let circuit = generator
        .try_generate_circuit_bootstrap_key(&accumulator, cbs_parameters, &mut rng)
        .unwrap();
    let resources = context.bootstrap_resources(&br).unwrap();
    let _cbs = CircuitBootstrapEvaluator::try_new(&resources, &circuit, &input_codec).unwrap();
    let _one_hot =
        OneHotCircuitBootstrapEvaluator::try_new(&resources, &circuit, &input_codec).unwrap();
    // This fixture tests key domains/binding, not a usable noise budget at tiny q.
}
