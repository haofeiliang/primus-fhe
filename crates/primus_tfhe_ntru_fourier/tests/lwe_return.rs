use primus_fft::{FftTable, RustFftTable, TfheFftTable, TorusFftValue};
use primus_modulus::NativeModulus;
use primus_tfhe_ntru_fourier::{
    DecompositionConfig, TfheConfig, TfheContext, TfheEvaluationError, TfheParameters,
};

use primus_encoding::RoundedCodec;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_test_allocations as allocations;
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;
const N: usize = 128;
const DIM: usize = 4;

fn check<T: TorusFftValue, Table: FftTable>() {
    let q = T::as_from(1u32 << 20);
    let external_modulus = BarrettModulus::new(q);
    for distr in [
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, 2),
        SecretKeyDistr::fixed_composition_ternary(DIM, 1, 1),
    ] {
        let decomposition = DecompositionConfig {
            log_basis: 5,
            level_count: None,
        };
        let config = TfheConfig {
            external_lwe: LweParameters::new(DIM, T::as_from(4u32), external_modulus, distr, 0.7),
            accumulator_modulus: NativeModulus::new(),
            poly_length: N,
            accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
            accumulator_noise_standard_deviation: 0.7,
            blind_rotation: DecompositionConfig {
                log_basis: 8,
                level_count: None,
            },
            key_switching: decomposition,
            key_switching_noise_standard_deviation: 0.7,
        };
        let context = TfheContext::<_, Table, _>::try_from_parameters(
            TfheParameters::try_from_config(config.clone()).unwrap(),
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(0x513251);
        let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
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
        let output_codec = RoundedCodec::new(
            T::as_from(8u32),
            context.parameters().accumulator_ntru().cipher_modulus(),
        );
        let decode_codec = RoundedCodec::new(T::as_from(8u32), external_modulus);
        let single = context
            .parameters()
            .compile_lookup_table_with_codec_fn(&output_codec, |m| T::as_from(m + 3))
            .unwrap();
        let many = context
            .parameters()
            .compile_interleaved_lookup_table_with_codec_fn(&output_codec, 3, |m, i| {
                T::as_from(m + i + 1)
            })
            .unwrap();
        let default = context
            .parameters()
            .compile_lookup_table_fn(|m| T::as_from(1 - m))
            .unwrap();
        let public = client
            .try_generate_public_key(context.parameters(), &mut rng)
            .unwrap();
        let encryptor = context.public_encryptor(&public).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        let mut output = context.allocate_lwe_ciphertext();
        let mut outputs = vec![output.clone(); 3];
        for m in [0usize, 1, 0] {
            let input = encryptor.encrypt_padded(T::as_from(m), &mut rng).unwrap();
            let (_, allocation) = allocations::measure(|| {
                evaluator.apply_lookup_table_to(&input, &single, &mut output);
                evaluator.apply_interleaved_lookup_table_to(&input, &many, &mut outputs);
            });
            assert_eq!(allocation.count, 0);
            assert!(output.as_ref().iter().all(|&x| x < q));
            assert_eq!(
                decode_codec.decode_value(decryptor.decrypt_phase(&output).unwrap()),
                T::as_from(m + 3)
            );
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(
                    decode_codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                    T::as_from(m + i + 1)
                );
            }
            evaluator.apply_lookup_table_to(&input, &default, &mut output);
            assert_eq!(decryptor.decrypt(&output).unwrap(), T::as_from(1 - m));
        }
        // Boolean correction is at q even though its internal LUT is encoded at Q.
        let mut boolean = context.boolean_evaluator(&server).unwrap();
        let bool_encrypt = context.boolean_encryptor(&client).unwrap();
        let bool_decrypt = context.boolean_decryptor(&client).unwrap();
        for a in [false, true] {
            for b in [false, true] {
                let a_ct = bool_encrypt.encrypt(a, &mut rng).unwrap();
                let b_ct = bool_encrypt.encrypt(b, &mut rng).unwrap();
                let result = boolean.and(&a_ct, &b_ct);
                assert_eq!(bool_decrypt.decrypt(&result).unwrap(), a && b);
            }
        }
        // Public factor products use the same Q-to-q return conversion.
        let scaled_q = primus_encoding::ScaledCodec::new(T::as_from(10u32), external_modulus);
        let scaled_ring = primus_encoding::ScaledCodec::new(
            T::as_from(10u32),
            context.parameters().accumulator_ntru().cipher_modulus(),
        );
        let program = context
            .compile_factorized_lookup_table_fn(&scaled_ring, 2, 2, |m, i| T::as_from(m + i))
            .unwrap();
        let mut factorized = context.factorized_evaluator(&server).unwrap();
        let input = encryptor.encrypt_padded(T::ONE, &mut rng).unwrap();
        factorized.apply_lookup_table_to(&input, &program, &mut outputs[..2]);
        for (i, output) in outputs[..2].iter().enumerate() {
            assert_eq!(
                scaled_q.decode_value(decryptor.decrypt_phase(output).unwrap()),
                T::as_from(i + 1)
            );
        }
        if distr.is_binary() {
            let sparse_server = context
                .try_generate_sparse_server_key(&client, 3, 8, &mut rng)
                .unwrap();
            let mut sparse = context.evaluator(&sparse_server).unwrap();
            let (_, allocation) = allocations::measure(|| {
                sparse.apply_interleaved_lookup_table_to(&input, &many, &mut outputs)
            });
            assert_eq!(allocation.count, 0);
            for (i, output) in outputs.iter().enumerate() {
                assert_eq!(
                    decode_codec.decode_value(decryptor.decrypt_phase(output).unwrap()),
                    T::as_from(i + 2)
                );
            }
        }
        // Changing only q must reject a server key before online work.
        let mut wrong = config;
        wrong.external_lwe = LweParameters::new(
            DIM,
            T::as_from(4u32),
            BarrettModulus::new(q / T::as_from(2u32)),
            distr,
            0.7,
        );
        let wrong = TfheContext::<_, Table, _>::try_from_parameters(
            TfheParameters::try_from_config(wrong).unwrap(),
        )
        .unwrap();
        assert_eq!(
            wrong.evaluator(&server).err(),
            Some(TfheEvaluationError::IncompatibleServerKey)
        );
    }
}

#[test]
fn returns_to_independent_lwe_at_smaller_modulus_without_allocations() {
    check::<u32, RustFftTable>();
    check::<u64, RustFftTable>();
    check::<u32, TfheFftTable>();
    check::<u64, TfheFftTable>();
}
