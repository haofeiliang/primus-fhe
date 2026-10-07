use primus_decompose::DecompositionBaseLog;
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::LweEncryptionParameters;
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use primus_tfhe_ntru_ntt::{
    BlindRotationConfig, DecompositionConfig, GadgetEncryptionConfig, TfheConfig, TfheContext,
    TfheEvaluationError, TfheParameters,
};

use primus_encoding::RoundedCodec;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::SecretKeyDistr;
use rand::{SeedableRng, rngs::StdRng};

const N: usize = 128;
const DIM: usize = 4;

fn check<T: FheUint, Table: MonomialNttTable<ValueT = T>>(ring_q: T) {
    let q = T::as_from(1u32 << 20);
    let external_modulus = PowOf2Modulus::new(q);
    for distr in [
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, 2),
        SecretKeyDistr::fixed_composition_ternary(DIM, 1, 1),
    ] {
        let decomposition = DecompositionConfig {
            log_basis: DecompositionBaseLog::new(5),
            level_count: None,
        };
        let config = TfheConfig {
            external_lwe: LweEncryptionParameters::new(
                LweDimension::new(DIM),
                external_modulus,
                distr,
                0.7,
            ),
            accumulator_modulus: BarrettModulus::new(ring_q),
            poly_length: PolyLength::new(N),
            accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
            blind_rotation: GadgetEncryptionConfig {
                decomposition: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            key_switching: GadgetEncryptionConfig {
                decomposition,
                noise_standard_deviation: 0.7,
            },
        };
        let context = TfheContext::<_, Table, _>::try_from_parameters(
            TfheParameters::try_from_config(config.clone()).unwrap(),
        )
        .unwrap();
        let input_codec = RoundedCodec::new(
            T::as_from(4u32),
            context.parameters().external_lwe().cipher_modulus(),
        );
        let mut rng = StdRng::seed_from_u64(0x513251);
        let blind_rotation = if distr.is_binary() {
            BlindRotationConfig::Sparse {
                copy_count: 3,
                bucket_count: 8,
            }
        } else {
            BlindRotationConfig::Classic
        };
        let (client, server) = context
            .try_generate_keys(blind_rotation, None, &mut rng)
            .unwrap();
        // Both distributions have even support and cannot form an invertible native NTRU key.
        assert_eq!(
            client
                .external_lwe_secret_key()
                .as_ref()
                .iter()
                .filter(|&&s| s != T::ZERO)
                .count(),
            2
        );
        let output_codecs = context
            .parameters()
            .pbs_codecs(
                PbsMessageConfig::new(T::as_from(4u32)).with_output_modulus(T::as_from(8u32)),
            )
            .unwrap();
        let compiler = context
            .parameters()
            .lookup_table_compiler(&output_codecs)
            .unwrap();
        let single = compiler.compile_fn(|m| T::as_from(m + 3)).unwrap();
        let many = compiler
            .compile_interleaved_fn(3, |m, i| T::as_from(m + i + 1))
            .unwrap();
        let codecs = context
            .parameters()
            .pbs_codecs(PbsMessageConfig::new(input_codec.plaintext_modulus()))
            .unwrap();
        let default = context
            .parameters()
            .lookup_table_compiler(&codecs)
            .unwrap()
            .compile_fn(|m| T::as_from(1 - m))
            .unwrap();
        let public = context
            .parameters()
            .try_generate_public_key(client.external_lwe_secret_key(), &mut rng)
            .unwrap();
        let encryptor = context.public_encryptor(&public, &input_codec).unwrap();
        let decryptor = context
            .decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let output_decryptor = context
            .decryptor(
                client.external_lwe_secret_key(),
                output_codecs.output_codec(),
            )
            .unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        let mut outputs = vec![output.clone(); 3];
        for m in [0usize, 1, 0] {
            let input = encryptor.encrypt_padded(T::as_from(m), &mut rng).unwrap();
            evaluator.apply_lookup_table_to(input.as_view(), &single, output.as_mut_view());
            evaluator.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut outputs);
            assert!(output.as_ref().iter().all(|&x| x < q));
            assert_eq!(
                output_decryptor.decrypt(output.as_view()).unwrap(),
                T::as_from(m + 3)
            );
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(
                    output_decryptor.decrypt(output.as_view()).unwrap(),
                    T::as_from(m + i + 1)
                );
            }
            evaluator.apply_lookup_table_to(input.as_view(), &default, output.as_mut_view());
            assert_eq!(
                decryptor.decrypt(output.as_view()).unwrap(),
                T::as_from(1 - m)
            );
        }
        // Boolean correction is at q even though its internal LUT is encoded at Q.
        let mut boolean = context.boolean_evaluator(&server, &input_codec).unwrap();
        let bool_encrypt = context
            .boolean_encryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let bool_decrypt = context
            .boolean_decryptor(client.external_lwe_secret_key(), &input_codec)
            .unwrap();
        for a in [false, true] {
            for b in [false, true] {
                let a_ct = bool_encrypt.encrypt(a, &mut rng).unwrap();
                let b_ct = bool_encrypt.encrypt(b, &mut rng).unwrap();
                let result = boolean.and(a_ct.as_view(), b_ct.as_view());
                assert_eq!(bool_decrypt.decrypt(result.as_view()).unwrap(), a && b);
            }
        }
        // Public factor products use the same Q-to-q return conversion.
        let mvb_codecs = context
            .parameters()
            .factorized_pbs_codecs(
                PbsMessageConfig::new(T::as_from(4u32)).with_output_modulus(T::as_from(10u32)),
            )
            .unwrap();
        let scaled_decryptor = context
            .decryptor(client.external_lwe_secret_key(), mvb_codecs.output_codec())
            .unwrap();
        let program = context
            .compile_factorized_lookup_table_fn(&mvb_codecs, 2, 2, |m, i| T::as_from(m + i))
            .unwrap();
        let mut pbs = context.evaluator(&server).unwrap();
        let mut factorized = primus_tfhe_ntru_ntt::FactorizedEvaluator::new(&pbs);
        let input = encryptor.encrypt_padded(T::ONE, &mut rng).unwrap();
        factorized.apply_lookup_table_to(input.as_view(), &program, &mut outputs[..2], &mut pbs);
        for (i, output) in outputs[..2].iter().enumerate() {
            assert_eq!(
                scaled_decryptor.decrypt(output.as_view()).unwrap(),
                T::as_from(i + 1)
            );
        }
        if distr.is_binary() {
            let sparse_server = context
                .try_generate_server_key(
                    &client,
                    BlindRotationConfig::Sparse {
                        copy_count: 3,
                        bucket_count: 8,
                    },
                    None,
                    &mut rng,
                )
                .unwrap();
            let mut sparse = context.evaluator(&sparse_server).unwrap();
            // Reuse the same public factors with the sparse key and independent
            // q-domain secret; each factor product must undergo its own Q→q return.
            let mut sparse_mvb = primus_tfhe_ntru_ntt::FactorizedEvaluator::new(&sparse);
            for m in [0usize, 1, 0] {
                let input = encryptor.encrypt_padded(T::as_from(m), &mut rng).unwrap();
                sparse_mvb.apply_lookup_table_to(
                    input.as_view(),
                    &program,
                    &mut outputs[..2],
                    &mut sparse,
                );
                for (i, output) in outputs[..2].iter().enumerate() {
                    assert!(output.as_ref().iter().all(|&x| x < q));
                    assert_eq!(
                        scaled_decryptor.decrypt(output.as_view()).unwrap(),
                        T::as_from(m + i)
                    );
                }
            }
            sparse.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut outputs);
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(
                    output_decryptor.decrypt(output.as_view()).unwrap(),
                    T::as_from(i + 2)
                );
            }
        }
        // Changing only q must reject a server key before online work.
        let mut wrong = config;
        wrong.external_lwe = LweEncryptionParameters::new(
            LweDimension::new(DIM),
            PowOf2Modulus::new(q / T::as_from(2u32)),
            distr,
            0.7,
        );
        let wrong = TfheContext::<_, Table, _>::try_from_parameters(
            TfheParameters::try_from_config(wrong).unwrap(),
        )
        .unwrap();
        assert_eq!(
            wrong.evaluator(&server).err(),
            Some(TfheEvaluationError::IncompatibleLweReturnKey)
        );
    }
}

#[test]
fn returns_to_independent_lwe_at_smaller_modulus() {
    check::<u32, U32NttTable>(132_120_577);
    check::<u64, U64NttTable>(1_125_899_906_826_241);
}
