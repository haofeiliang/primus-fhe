use primus_decompose::DecompositionBaseLog;
use primus_lattice::{GlweDimension, LweDimension};
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    BlindRotationAlgorithm, ClientKey, FactorizedLookupTable, GadgetEncryptionConfig,
    InterleavedLookupTable, KeyGenerator, LookupTable, LookupTableError, NttFactorizedLookupTable,
    PbsOrder, PbsParameters, TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 128;
const Q: u32 = 132_120_577;
const DOMAIN: usize = 8;

fn context(order: PbsOrder, distribution: SecretKeyDistr) -> TfheContext<u32, U32NttTable> {
    let modulus = BarrettModulus::new(Q);
    let parameters = PbsParameters::try_new(
        (LweParameters::new(LweDimension::new(8), 15, modulus, distribution, 0.7))
            .into_encryption_parameters(),
        primus_glwe::GgswParameters::try_with_basis(
            &(
                // d=2 also exercises multiplication of all mask components, not just a,b.
                GlweParameters::new(
                    GlweDimension::new(2),
                    PolyLength::new(N),
                    15,
                    modulus,
                    SecretKeyDistr::UniformBinary,
                    0.7,
                )
            ),
            ApproxSignedBasis::new(Some(Q), DecompositionBaseLog::new(8), None),
        )
        .unwrap(),
        GadgetEncryptionConfig {
            decomposition: ApproxSignedBasis::new(Some(Q), DecompositionBaseLog::new(8), None),
            noise_standard_deviation: 0.7,
        },
        order,
    )
    .unwrap();
    TfheContext::try_new(
        parameters,
        U32NttTable::new(PolyLength::new(N), modulus).unwrap(),
    )
    .unwrap()
}

fn value(m: usize, i: usize) -> u32 {
    match i % 3 {
        0 => (7 - m) as u32,
        1 => (m % 2) as u32,
        _ => u32::from(m >= 3),
    }
}

#[test]
fn factorized_pbs_reuses_workspace_and_preserves_both_external_secrets() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context(order, SecretKeyDistr::fixed_hamming_weight_binary(8, 2));
        let mvb_codecs = context
            .parameters()
            .factorized_pbs_codecs(PbsMessageConfig::new(15).with_output_modulus(8))
            .unwrap();
        let input_codec = *mvb_codecs.input_codec();
        let codec = *mvb_codecs.lut_output_codec();
        let modulus = context.parameters().blind_rotation_ggsw().cipher_modulus();
        let mut rng = StdRng::seed_from_u64(0x5034_3201);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let classic = generator
            .try_generate_server_key(&client, BlindRotationAlgorithm::Classic, None, &mut rng)
            .unwrap();
        let sparse = generator
            .try_generate_server_key(
                &client,
                BlindRotationAlgorithm::Sparse {
                    copy_count: 3,
                    bucket_count: 4,
                },
                None,
                &mut rng,
            )
            .unwrap();
        let dimension = context.parameters().external_lwe_dimension().get();
        assert_eq!(
            dimension,
            (LweDimension::new(if order == PbsOrder::BootstrapKeyswitch {
                8
            } else {
                2 * N
            }))
            .get()
        );
        let encryptor = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let decryptor = context
            .decryptor(client.external_lwe_secret_key(), &codec)
            .unwrap();
        let check = |outputs: &[LweCiphertext<u32>], message: usize| {
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(output.dimension(), dimension);
                assert_eq!(
                    decryptor.decrypt(output.as_view()).unwrap(),
                    value(message, i)
                );
            }
        };

        for key in [&classic, &sparse] {
            let mut pbs = context.evaluator(key).unwrap();
            let mut evaluator = primus_tfhe_glwe_ntt::FactorizedEvaluator::new(&pbs);
            for count in [1, 3, 17] {
                let lut = context
                    .compile_factorized_lookup_table_fn(&mvb_codecs, DOMAIN, count, value)
                    .unwrap();
                assert_eq!(
                    (
                        lut.input_domain_len(),
                        lut.output_count(),
                        lut.output_plaintext_modulus()
                    ),
                    (DOMAIN, count, 8)
                );
                let mut outputs = vec![LweCiphertext::zero(dimension); count];
                for message in [0, 3, 7] {
                    let input = encryptor.encrypt_padded(message as u32, &mut rng).unwrap();
                    evaluator.apply_lookup_table_to(input.as_view(), &lut, &mut outputs, &mut pbs);
                    check(&outputs, message);
                    if count == 3 && message == 3 {
                        assert_eq!(
                            outputs,
                            evaluator.apply_lookup_table(input.as_view(), &lut, &mut pbs)
                        );
                        // Same functions AND Scaled centers in both existing baselines.
                        let interleaved =
                            InterleavedLookupTable::try_new(
                                DOMAIN,
                                PolyLength::new(N),
                                count,
                                15,
                                modulus,
                                modulus,
                                |m, i| {
                                    Ok(codec
                                        .encode_value(value(m, i), PlaintextEmbedding::Unsigned))
                                },
                            )
                            .unwrap();
                        pbs.apply_interleaved_lookup_table_to(
                            input.as_view(),
                            &interleaved,
                            &mut outputs,
                        );
                        check(&outputs, message);
                        for (i, output) in outputs.iter_mut().enumerate() {
                            let single = LookupTable::try_new(
                                DOMAIN,
                                PolyLength::new(N),
                                15,
                                modulus,
                                modulus,
                                |m| {
                                    Ok(codec
                                        .encode_value(value(m, i), PlaintextEmbedding::Unsigned))
                                },
                            )
                            .unwrap();
                            pbs.apply_lookup_table_to(
                                input.as_view(),
                                &single,
                                output.as_mut_view(),
                            );
                        }
                        check(&outputs, message);
                    }
                }
            }
        }
        // 17 outputs require 32 interleaved slots: N/32=4 < D=8. MVB above works.
        assert!(matches!(
            InterleavedLookupTable::try_new(
                DOMAIN,
                PolyLength::new(N),
                17,
                15,
                modulus,
                modulus,
                |_, _| Ok(0)
            ),
            Err(LookupTableError::PlaintextDomainTooLarge { .. })
        ));

        let lut = context
            .compile_factorized_lookup_table_fn(&mvb_codecs, DOMAIN, 3, value)
            .unwrap();
        // Same q,N, but deliberately a different instance.
        let other_context = self::context(order, SecretKeyDistr::fixed_hamming_weight_binary(8, 2));

        let foreign = other_context
            .compile_factorized_lookup_table_fn(&mvb_codecs, DOMAIN, 3, value)
            .unwrap();
        let mut pbs = context.evaluator(&classic).unwrap();
        let mut evaluator = primus_tfhe_glwe_ntt::FactorizedEvaluator::new(&pbs);
        let input = encryptor.encrypt_padded(3, &mut rng).unwrap();
        let wrong = LweCiphertext::zero(dimension - 1);
        let mut foreign_pbs = other_context.evaluator(&classic).unwrap();
        for case in 0..5 {
            let mut outputs = vec![input.clone(); if case == 0 { 2 } else { 3 }];
            if case == 1 {
                outputs[2] = wrong.clone();
            }
            let before = outputs.clone();
            assert!(
                catch_unwind(AssertUnwindSafe(|| evaluator.apply_lookup_table_to(
                    if case == 2 {
                        wrong.as_view()
                    } else {
                        input.as_view()
                    },
                    if case == 3 { &foreign } else { &lut },
                    &mut outputs,
                    if case == 4 {
                        &mut foreign_pbs
                    } else {
                        &mut pbs
                    }
                )))
                .is_err()
            );
            assert_eq!(outputs, before);
        }
        check(
            &evaluator.apply_lookup_table(input.as_view(), &lut, &mut pbs),
            3,
        );

        // Preparing raw coefficient programs rejects each incompatible metadata field.
        for (n, t, input_q, output_q) in [(N / 2, 15, Q, Q), (N, 15, 97, Q), (N, 15, Q, 97)] {
            let raw = FactorizedLookupTable::try_new(
                2,
                PolyLength::new(n),
                1,
                &RoundedCodec::new(t, BarrettModulus::new(input_q)),
                &ScaledCodec::new(8, BarrettModulus::new(output_q)),
                |_, _| 0,
            )
            .unwrap();
            assert!(
                catch_unwind(AssertUnwindSafe(|| NttFactorizedLookupTable::new(
                    &context, raw
                )))
                .is_err()
            );
        }
        assert!(matches!(
            context.compile_factorized_lookup_table_fn(
                &PbsMessageConfig::new(15)
                    .with_output_modulus(8)
                    .try_factorized_codecs(
                        input_codec.ciphertext_modulus(),
                        BarrettModulus::new(97)
                    )
                    .unwrap(),
                DOMAIN,
                3,
                value
            ),
            Err(LookupTableError::OutputModulusMismatch)
        ));
    }
}

// The broad binary/classic/sparse matrix above owns program-validation cases.
// This case protects the ternary BR -> public-factor composition in both orders.
#[test]
fn factorized_pbs_accepts_ternary_controls() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context(order, SecretKeyDistr::fixed_composition_ternary(8, 2, 2));
        // Cover the default without adding another key-generation case.
        let messages = if order == PbsOrder::BootstrapKeyswitch {
            PbsMessageConfig::new(16)
        } else {
            PbsMessageConfig::new(15).with_output_modulus(8)
        };
        let mvb_codecs = context
            .parameters()
            .factorized_pbs_codecs(messages)
            .unwrap();
        let input_codec = *mvb_codecs.input_codec();
        let codec = *mvb_codecs.output_codec();
        let mut rng = StdRng::seed_from_u64(0x0054_334d_5642);
        let (client, server) = context
            .try_generate_keys(BlindRotationAlgorithm::Classic, None, &mut rng)
            .unwrap();
        let lut = context
            .compile_factorized_lookup_table_fn(&mvb_codecs, DOMAIN, 3, value)
            .unwrap();
        let encryptor = context
            .encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let decryptor = context
            .decryptor(client.external_lwe_secret_key(), &codec)
            .unwrap();
        let mut pbs = context.evaluator(&server).unwrap();
        let mut evaluator = primus_tfhe_glwe_ntt::FactorizedEvaluator::new(&pbs);
        let mut outputs =
            vec![LweCiphertext::zero(context.parameters().external_lwe_dimension().get()); 3];
        for message in [0, 3, 7] {
            let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
            evaluator.apply_lookup_table_to(input.as_view(), &lut, &mut outputs, &mut pbs);
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(
                    decryptor.decrypt(output.as_view()).unwrap(),
                    value(message as usize, i)
                );
            }
        }
    }
}
