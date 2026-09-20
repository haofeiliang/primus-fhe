use primus_tfhe::ProgrammableBootstrap as _;
use primus_tfhe::ProgrammableBootstrapInterleaved as _;
use std::panic::{AssertUnwindSafe, catch_unwind};

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_test_allocations as allocations;
use primus_tfhe_glwe_ntt::{
    ClientKey, FactorizedLookupTable, InterleavedLookupTable, KeyGenerator, LookupTable,
    LookupTableError, NttFactorizedLookupTable, PbsOrder, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

const N: usize = 128;
const Q: u32 = 132_120_577;
const DOMAIN: usize = 8;

fn context(order: PbsOrder, distribution: SecretKeyDistr) -> TfheContext<u32, U32NttTable> {
    let modulus = BarrettModulus::new(Q);
    let parameters = TfheParameters::try_new(
        LweParameters::new(8, 15, modulus, distribution, 0.7),
        // d=2 also exercises multiplication of all mask components, not just a,b.
        GlweParameters::new(2, N, 15, modulus, SecretKeyDistr::UniformBinary, 0.7),
        ApproxSignedBasis::new(Some(Q), 8, None),
        ApproxSignedBasis::new(Some(Q), 8, None),
        order,
    )
    .unwrap();
    TfheContext::try_new(
        parameters,
        U32NttTable::new(N.trailing_zeros(), modulus).unwrap(),
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
        let modulus = context.parameters().accumulator_glwe().cipher_modulus();
        let codec = ScaledCodec::new(8, modulus);
        let mut rng = StdRng::seed_from_u64(0x5034_3201);
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let classic = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let sparse = generator
            .try_generate_sparse_server_key(&client, 3, 4, None, &mut rng)
            .unwrap();
        let dimension = context.parameters().external_lwe_dimension();
        assert_eq!(
            dimension,
            if order == PbsOrder::BootstrapKeyswitch {
                8
            } else {
                2 * N
            }
        );
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let check = |outputs: &[LweCiphertext<u32>], message: usize| {
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(output.dimension(), dimension);
                assert_eq!(
                    codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                    value(message, i)
                );
            }
        };

        for key in [&classic, &sparse] {
            let mut evaluator = primus_tfhe_glwe_ntt::FactorizedEvaluator::from_bootstrapper(
                context.evaluator(key).unwrap(),
            );
            for count in [1, 3, 17] {
                let (lut, allocation) = allocations::measure(|| {
                    context
                        .compile_factorized_lookup_table_fn(&codec, DOMAIN, count, value)
                        .unwrap()
                });
                assert_eq!(
                    allocation.count, 2,
                    "preparation must reuse the factor buffer"
                );
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
                    let (_, allocation) = allocations::measure(|| {
                        evaluator.apply_lookup_table_to(&input, &lut, &mut outputs)
                    });
                    assert_eq!(allocation.count, 0, "MVB must reuse its workspace");
                    check(&outputs, message);
                    if count == 3 && message == 3 {
                        assert_eq!(outputs, evaluator.apply_lookup_table(&input, &lut));
                        // Same functions AND Scaled centers in both existing baselines.
                        let interleaved =
                            InterleavedLookupTable::try_new(
                                DOMAIN,
                                N,
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
                        evaluator
                            .bootstrapper_mut()
                            .apply_interleaved_lookup_table_to(&input, &interleaved, &mut outputs);
                        check(&outputs, message);
                        for (i, output) in outputs.iter_mut().enumerate() {
                            let single =
                                LookupTable::try_new(DOMAIN, N, 15, modulus, modulus, |m| {
                                    Ok(codec
                                        .encode_value(value(m, i), PlaintextEmbedding::Unsigned))
                                })
                                .unwrap();
                            evaluator
                                .bootstrapper_mut()
                                .apply_lookup_table_to(&input, &single, output);
                        }
                        check(&outputs, message);
                    }
                }
            }

            let (_, recovered) = allocations::measure(|| evaluator.into_bootstrapper());
            assert_eq!(recovered.count, 0, "recovery must retain PBS allocations");
        }
        // 17 outputs require 32 interleaved slots: N/32=4 < D=8. MVB above works.
        assert!(matches!(
            InterleavedLookupTable::try_new(DOMAIN, N, 17, 15, modulus, modulus, |_, _| Ok(0)),
            Err(LookupTableError::PlaintextDomainTooLarge { .. })
        ));

        let lut = context
            .compile_factorized_lookup_table_fn(&codec, DOMAIN, 3, value)
            .unwrap();
        // Same q,N, but deliberately a different instance.
        let other_context = self::context(order, SecretKeyDistr::fixed_hamming_weight_binary(8, 2));
        let foreign = other_context
            .compile_factorized_lookup_table_fn(&codec, DOMAIN, 3, value)
            .unwrap();
        let mut evaluator = context.factorized_evaluator(&classic).unwrap();
        let input = encryptor.encrypt_padded(3, &mut rng).unwrap();
        let wrong = LweCiphertext::zero(dimension - 1);
        for case in 0..4 {
            let mut outputs = vec![input.clone(); if case == 0 { 2 } else { 3 }];
            if case == 1 {
                outputs[2] = wrong.clone();
            }
            let before = outputs.clone();
            assert!(
                catch_unwind(AssertUnwindSafe(|| evaluator.apply_lookup_table_to(
                    if case == 2 { &wrong } else { &input },
                    if case == 3 { &foreign } else { &lut },
                    &mut outputs,
                )))
                .is_err()
            );
            assert_eq!(outputs, before);
        }
        check(&evaluator.apply_lookup_table(&input, &lut), 3);

        // Preparing raw coefficient programs rejects each incompatible metadata field.
        for (n, t, input_q, output_q) in [
            (N / 2, 15, Q, Q),
            (N, 8, Q, Q),
            (N, 15, 97, Q),
            (N, 15, Q, 97),
        ] {
            let raw = FactorizedLookupTable::try_new(
                2,
                n,
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
                &ScaledCodec::new(8, BarrettModulus::new(97)),
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
fn factorized_pbs_accepts_ternary_controls_without_online_allocation() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let context = context(order, SecretKeyDistr::fixed_composition_ternary(8, 2, 2));
        let mut rng = StdRng::seed_from_u64(0x0054_334d_5642);
        let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
        let codec = ScaledCodec::new(8, context.parameters().accumulator_glwe().cipher_modulus());
        let lut = context
            .compile_factorized_lookup_table_fn(&codec, DOMAIN, 3, value)
            .unwrap();
        let encryptor = context.encryptor(&client).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let mut evaluator = context.factorized_evaluator(&server).unwrap();
        let mut outputs =
            vec![LweCiphertext::zero(context.parameters().external_lwe_dimension()); 3];
        for message in [0, 3, 7] {
            let input = encryptor.encrypt_padded(message, &mut rng).unwrap();
            let (_, allocation) = allocations::measure(|| {
                evaluator.apply_lookup_table_to(&input, &lut, &mut outputs)
            });
            assert_eq!(allocation.count, 0);
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(
                    codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                    value(message as usize, i)
                );
            }
        }
    }
}
