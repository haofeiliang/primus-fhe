//! Gadget-scale phases and actual CMux/external-product consumption;
//! parameter-constructor boundaries belong to the common family crate.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::RoundedCodec;
use primus_encoding::ScaledCodec;
use primus_lattice::LweDimension;
use primus_lwe::LweParameters;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, NttNgswCiphertext, NttNtruSecretKey, SecretKeyDistr};
use primus_ntt::U64NttTable;
use primus_poly::PolyLength;
use primus_poly::Polynomial;
use primus_tfhe::PbsMessageConfig;
use primus_tfhe_ntru_ntt::{
    BlindRotationConfig, CircuitBootstrapConfig, CircuitBootstrapEvaluator, DecompositionConfig,
    GadgetEncryptionConfig, TfheContext, TfheParameters,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const N: usize = 64;
const Q: u64 = 1_125_899_906_826_241;

// Reuse one evaluator across controls, then consume its gadget ciphertexts.
fn circuit_bootstrap(distr: SecretKeyDistr, sparse: bool) {
    let modulus = BarrettModulus::new(Q);
    let lwe = LweParameters::new(
        LweDimension::new(16),
        4,
        PowOf2Modulus::new(1u64 << 24),
        distr,
        0.7,
    );
    let accumulator = NtruParameters::new(
        PolyLength::new(N),
        4,
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let blind_rotation_basis = ApproxSignedBasis::new(
        accumulator.cipher_modulus_value(),
        DecompositionBaseLog::new(10),
        None,
    );

    let tfhe = TfheParameters::try_new(
        lwe.into_encryption_parameters(),
        NlevParameters::try_with_basis(&accumulator, blind_rotation_basis).unwrap(),
        GadgetEncryptionConfig {
            decomposition: primus_tfhe_ntru::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
    )
    .unwrap();
    let context = TfheContext::<_, U64NttTable, _>::try_from_parameters(tfhe).unwrap();
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0x004e_5454_5f43_4253);
    // Three gadget levels exercise multiple scales and an internal padding slot.
    let levels = 3;
    let cbs_config = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(levels)),
        },
        trace: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        scheme_switch: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(10),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
    };
    // CBS-only material can be generated and bound before any return key exists.
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
    let br = generator
        .try_generate_blind_rotation_key(&client, blind_rotation, &mut rng)
        .unwrap();
    let circuit = generator
        .try_generate_circuit_bootstrap_key(
            client.accumulator_ntru_secret_key(),
            primus_tfhe_ntru_ntt::CircuitBootstrapParameters::try_from_config(
                context.parameters(),
                cbs_config,
            )
            .unwrap(),
            &mut rng,
        )
        .unwrap();
    {
        let resources = context.bootstrap_resources(&br).unwrap();
        let _cbs = CircuitBootstrapEvaluator::try_new(&resources, &circuit, &input_codec).unwrap();
    }
    let return_key = context
        .parameters()
        .try_generate_lwe_return_key(&client, &mut rng)
        .unwrap();
    let server = primus_tfhe_ntru_ntt::ServerKey::new(br, return_key, Some(circuit));
    let circuit_key = server.circuit_bootstrap_key().unwrap();
    let parameters = circuit_key.parameters();
    // Classic exposes coordinate controls; sparse owns coefficient buckets.
    if let Some(controls) = server.blind_rotation_key().classic_controls() {
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
        .evaluator(&server)
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
        .bootstrap_resources(server.blind_rotation_key())
        .unwrap();
    let mut evaluator =
        CircuitBootstrapEvaluator::try_new(&resources, circuit_key, &input_codec).unwrap();
    let mut standalone_control = evaluator.allocate_output();
    evaluator.circuit_bootstrap_to(input.as_view(), &mut standalone_control, &mut resources);
    let mut pbs =
        primus_tfhe_ntru_ntt::Evaluator::try_from_resources(resources, server.key_switching_key())
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
    // Rebind the same CBS key to t=8; the final zero overwrites a nonzero control.
    for (t, bit) in [(4u64, 1u64), (8, 1), (8, 0)] {
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
        evaluator = CircuitBootstrapEvaluator::try_new(
            pbs.bootstrap_resources(),
            circuit_key,
            &input_codec,
        )
        .unwrap();
        let input = encryptor.encrypt_padded(bit, &mut rng).unwrap();
        evaluator.circuit_bootstrap_to(
            input.as_view(),
            &mut control,
            pbs.bootstrap_resources_mut(),
        );
        evaluator.cmux_to(
            &control,
            &choices[0],
            &choices[1],
            &mut selected,
            pbs.bootstrap_resources_mut(),
        );
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
            bit
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
                let value = (u128::from(scalar) * u128::from(f.unsigned_abs()) * u128::from(bit))
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
        assert_eq!(decoded, vec![if bit == 0 { 1 } else { 3 }; N]);
        assert_eq!(decoded_product, vec![3 * bit; N]);
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
    let other_context =
        TfheContext::<_, U64NttTable, _>::try_from_parameters(context.parameters().clone())
            .unwrap();
    let mut other_resources = other_context
        .bootstrap_resources(server.blind_rotation_key())
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
    let return_key = server.key_switching_key().clone();
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

// A valid accumulator at Q can exceed external q. Only return generation needs
// the latter bound; CBS-only key generation and binding must stay independent.
#[test]
fn independent_cbs_material_does_not_require_a_return_key() {
    use primus_tfhe_ntru_ntt::{
        CircuitBootstrapParameters, ClientKey, KeyGenerator, OneHotCircuitBootstrapEvaluator,
        TfheKeyError,
    };
    let full = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(4),
        level_count: None,
    };
    let config = primus_tfhe_ntru_ntt::TfheConfig {
        external_lwe: primus_lwe::LweEncryptionParameters::new(
            LweDimension::new(2),
            primus_modulus::PowOf2Modulus::new(16u32),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        accumulator_modulus: primus_modulus::BarrettModulus::new(65_537u32),
        poly_length: PolyLength::new(32),
        accumulator_secret_key_distr: SecretKeyDistr::gaussian(3.2),
        blind_rotation: GadgetEncryptionConfig {
            decomposition: full,
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(2),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
    };
    // Generated keys also need the q bound when the sampler support is wider.
    // Fixed seeds cover both rejection and an accepted sample below that support bound.
    for (q, accepted) in [(16u32, false), (64, true)] {
        let mut candidate = config.clone();
        candidate.accumulator_secret_key_distr = SecretKeyDistr::gaussian(12.8);
        candidate.external_lwe = primus_lwe::LweEncryptionParameters::new(
            LweDimension::new(2),
            primus_modulus::PowOf2Modulus::new(q),
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let candidate = TfheContext::<_, primus_ntt::U32NttTable, _>::try_from_parameters(
            TfheParameters::try_from_config(candidate).unwrap(),
        )
        .unwrap();
        let mut generator = KeyGenerator::new(&candidate);
        let mut sample_rng = StdRng::seed_from_u64(42);
        let sample = generator.try_generate_client_key(&mut sample_rng).unwrap();
        let fits = sample
            .accumulator_ntru_secret_key()
            .as_slice()
            .iter()
            .all(|s| s.unsigned_abs() < q);
        assert_eq!(fits, accepted);
        let result = generator.try_generate(
            BlindRotationConfig::Classic,
            None,
            &mut StdRng::seed_from_u64(42),
        );
        assert_eq!(
            result.err(),
            (!fits).then_some(primus_tfhe_ntru::KeyGenerationError::ClientKey(
                TfheKeyError::AccumulatorSecretOutsideLweModulus
            ),)
        );
    }
    let parameters = TfheParameters::try_from_config(config).unwrap();
    let context =
        TfheContext::<_, primus_ntt::U32NttTable, _>::try_from_parameters(parameters).unwrap();
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
    assert_eq!(
        context
            .parameters()
            .try_generate_lwe_return_key(&client, &mut rng)
            .err(),
        Some(TfheKeyError::AccumulatorSecretOutsideLweModulus)
    );
    assert_eq!(rng.random::<u64>(), untouched.random::<u64>());
    let mut generator = KeyGenerator::new(&context);
    let br = generator
        .try_generate_classic_blind_rotation_key(&client, &mut rng)
        .unwrap();
    let cbs_parameters = CircuitBootstrapParameters::try_from_config(
        context.parameters(),
        CircuitBootstrapConfig {
            output: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(1)),
            },
            trace: GadgetEncryptionConfig {
                decomposition: full,
                noise_standard_deviation: 0.7,
            },
            scheme_switch: GadgetEncryptionConfig {
                decomposition: full,
                noise_standard_deviation: 0.7,
            },
        },
    )
    .unwrap();
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
