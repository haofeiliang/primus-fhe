//! Sparse key entries, dummy selectors and support mapping are checked
//! independently of end-to-end PBS; invalid imports must precede sampling.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{Complex64, FftTable, RustFftTable, TfheFftTable};
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_lattice::{ggsw::FourierGgsw, workspace::FourierGlweExternalProductWorkspace};
use primus_lwe::LweSecretKey;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe::sparse::BucketMapError;
use primus_tfhe_glwe_fourier::{
    BlindRotationKey, BlindRotationMethod, ClientKey, GadgetEncryptionConfig, KeyGenerator,
    PbsOrder, PbsParameters, SparseBootstrappingKeyError as Error, TfheContext,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 64;

fn context<Table: FftTable>(
    distribution: SecretKeyDistr,
) -> (
    primus_tfhe_glwe_fourier::PbsParameters<u64>,
    TfheContext<u64, Table>,
) {
    let modulus = NativeModulus::new();
    let parameters = PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(16),
            cipher_modulus: modulus.into(),
            secret_key_distr: distribution,
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(N),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(6)),
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(6)),
            },
            noise_standard_deviation: 0.7,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(4),
        order: PbsOrder::KeyswitchBootstrap,
    })
    .unwrap();
    let context = TfheContext::from_parameters(parameters.clone());
    (parameters, context)
}

fn check_selectors<Table: FftTable>() {
    let (_, context) = context::<Table>(SecretKeyDistr::fixed_hamming_weight_binary(16, 4));
    let input_codec = primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
    let mut generator = KeyGenerator::new(&context);
    let mut rng = StdRng::seed_from_u64(0x5350_4152_5345);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let glwe = context.parameters().blind_rotation_params();
    let mut accumulator_client = context
        .accumulator_client(client.glwe_secret_key(), input_codec.plaintext_modulus())
        .unwrap();
    let mut message = vec![0; N];
    message[0] = 1;
    message[N - 1] = 2;
    // Nontrivial masks and both ends of the polynomial exercise every GGSW row
    // and negacyclic multiplication after the coefficient/Fourier round trip.
    let input = accumulator_client.encrypt(&message, &mut rng);
    let size = context.parameters().blind_rotation_params().size();
    let mut fft = context.new_fft_engine();
    let mut external_product = FourierGlweExternalProductWorkspace::new(size);
    let mut control = FourierGgsw::<Vec<Complex64>>::zero(size.fourier_ggsw_len());
    let mut product = context.allocate_accumulator_ciphertext();
    let mut decoded = vec![0; N];

    // The second map must have at least one bucket with no public entries.
    for (copy_count, bucket_count) in [(3, 8), (1, 17)] {
        let BlindRotationKey::Sparse(key) = generator
            .try_generate_blind_rotation_key(
                &client,
                BlindRotationMethod::Sparse {
                    copy_count,
                    bucket_count,
                },
                &mut rng,
            )
            .unwrap()
        else {
            panic!("sparse BR configuration must generate sparse material");
        };
        assert_eq!(key.input_dimension(), LweDimension::new(16));
        assert_eq!(key.hamming_weight(), 4);
        assert_eq!(key.copy_count(), copy_count);
        assert_eq!(key.bucket_count(), bucket_count);
        assert_eq!(key.cipher_modulus(), None);
        assert_eq!(key.input_modulus(), glwe.cipher_modulus());
        assert_eq!(key.size(), size);
        assert_eq!(
            key.basis(),
            context.parameters().blind_rotation_params().basis()
        );
        assert_eq!(
            key.as_slice().len(),
            (16 * copy_count + bucket_count) * size.ggsw_len()
        );
        let mut copies = [0; 16];
        let mut selected = [0; 16];
        let mut dummy_count = 0;
        for bucket in 0..key.bucket_count() {
            let (indices, ciphertexts) = key.bucket(bucket);
            assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
            let mut bucket_selection_count = 0;
            let mut ciphertext_count = 0;
            for (slot, ciphertext) in ciphertexts.enumerate() {
                ciphertext_count += 1;
                ciphertext.write_fourier_form(&mut control, &mut fft);
                control.external_product_to(
                    &input,
                    &mut product,
                    key.basis(),
                    &mut fft,
                    &mut external_product,
                );
                accumulator_client.decrypt_to(&product, &mut decoded);
                let bit = decoded[0];
                assert!(bit <= 1);
                for (&actual, &expected) in decoded.iter().zip(&message) {
                    assert_eq!(actual, bit * expected);
                }
                bucket_selection_count += bit;
                if slot < indices.len() {
                    copies[indices[slot]] += 1;
                    selected[indices[slot]] += bit;
                } else {
                    dummy_count += bit;
                }
            }
            assert_eq!(ciphertext_count, indices.len() + 1);
            assert_eq!(bucket_selection_count, 1);
        }
        assert_eq!(copies, [copy_count; 16]);
        assert_eq!(selected.as_slice(), client.small_lwe_secret_key().as_ref());
        assert_eq!(dummy_count as usize, bucket_count - 4);
    }
}

#[test]
fn encrypted_selectors_and_dummies_work_with_both_fft_tables() {
    check_selectors::<RustFftTable>();
    check_selectors::<TfheFftTable>();
}

#[test]
fn sparse_key_errors_do_not_consume_randomness() {
    let distribution = SecretKeyDistr::fixed_hamming_weight_binary(16, 4);
    let (context_parameters, context) = self::context::<RustFftTable>(distribution);

    let client = ClientKey::generate(context.parameters(), &mut StdRng::seed_from_u64(42));
    let malformed = ClientKey::new(
        LweSecretKey::new(
            vec![2; 16],
            distribution,
            context.parameters().small_lwe().cipher_modulus(),
        ),
        client.glwe_secret_key().clone(),
        client.pbs_order(),
    );
    let mut generator = KeyGenerator::new(&context);
    // Fresh generation must reject public geometry before sampling either secret.
    for (copy_count, bucket_count) in [(0, 8), (9, 8), (3, 3)] {
        let mut rng = StdRng::seed_from_u64(43);
        assert_eq!(
            generator
                .try_generate_with_parameters(
                    context_parameters.glwe_key_switching(),
                    BlindRotationMethod::Sparse {
                        copy_count,
                        bucket_count
                    },
                    &mut rng
                )
                .err(),
            Some(Error::BucketMap(BucketMapError::InvalidBucketParameters).into())
        );
        assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());
    }

    let wrong_order = ClientKey::new(
        client.small_lwe_secret_key().clone(),
        client.glwe_secret_key().clone(),
        PbsOrder::BootstrapKeyswitch,
    );
    let mut rng = StdRng::seed_from_u64(43);
    let expected = generator
        .try_generate_server_key_with_parameters(
            context_parameters.glwe_key_switching(),
            &wrong_order,
            BlindRotationMethod::Classic,
            &mut rng,
        )
        .err()
        .unwrap();
    assert!(matches!(
        expected,
        primus_tfhe_glwe::KeyGenerationError::ClientKey(_)
    ));
    assert_eq!(
        generator
            .try_generate_sparse_blind_rotation_key(&wrong_order, 3, 8, &mut rng)
            .err(),
        Some(expected.clone())
    );
    assert_eq!(
        generator
            .try_generate_server_key_with_parameters(
                context_parameters.glwe_key_switching(),
                &wrong_order,
                BlindRotationMethod::Sparse {
                    copy_count: 3,
                    bucket_count: 8
                },
                &mut rng
            )
            .err(),
        Some(expected)
    );
    assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());

    for (client, copies, buckets, error) in [
        (
            &client,
            0,
            8,
            Error::BucketMap(BucketMapError::InvalidBucketParameters).into(),
        ),
        (&client, 3, usize::MAX, Error::StorageSizeOverflow.into()),
        (
            &malformed,
            3,
            8,
            primus_tfhe_glwe::KeyGenerationError::ClientKey(
                primus_tfhe_glwe::TfheKeyError::InvalidLweSecretKeyCoefficient,
            ),
        ),
    ] {
        let mut rng = StdRng::seed_from_u64(43);
        let result =
            generator.try_generate_sparse_blind_rotation_key(client, copies, buckets, &mut rng);
        assert_eq!(result.err(), Some(error));
        assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());
    }
}
