//! Sparse key entries, dummy selectors and support mapping are checked
//! independently of end-to-end PBS; invalid imports must precede sampling.

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::PlaintextEmbedding;
use primus_glwe::{GlweCiphertext, NttGlweSecretKey, SecretKeyDistr};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lattice::{ggsw::NttGgsw, glwe::NttGlwe, workspace::NttGlweExternalProductWorkspace};
use primus_lwe::LweSecretKey;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_poly::{PolyLength, PolynomialOwned};
use primus_tfhe::sparse::BucketMapError;
use primus_tfhe_glwe_ntt::{
    BlindRotationKey, BlindRotationMethod, ClientKey, GadgetEncryptionConfig, KeyGenerator,
    PbsOrder, PbsParameters, SparseBootstrappingKeyError as Error, TfheContext,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

const N: usize = 64;
const Q: u32 = 132_120_577;

fn context(
    distribution: SecretKeyDistr,
) -> (
    primus_tfhe_glwe_ntt::PbsParameters<u32>,
    TfheContext<u32, U32NttTable>,
) {
    let modulus = BarrettModulus::new(Q);
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
                log_basis: DecompositionBaseLog::new(9),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(9),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(4),
        order: PbsOrder::KeyswitchBootstrap,
    })
    .unwrap();
    let ntt = U32NttTable::new(PolyLength::new(N), modulus).unwrap();
    let context = TfheContext::try_new(parameters.clone(), ntt).unwrap();
    (parameters, context)
}

#[test]
fn encrypted_selections_cover_the_support_once_with_dummy_per_bucket() {
    let (_, context) = self::context(SecretKeyDistr::fixed_hamming_weight_binary(16, 4));

    let mut generator = KeyGenerator::new(&context);
    let mut rng = StdRng::seed_from_u64(0x5350_4152_5345);
    let client = ClientKey::generate(context.parameters(), &mut rng);
    let ntt = context.table();
    let glwe = primus_glwe::GlweParameters::try_from_glev(
        context.parameters().blind_rotation_params(),
        primus_encoding::ScaledCodec::new(8, context.parameters().cipher_modulus()),
    )
    .unwrap();
    let output_key = NttGlweSecretKey::from_coeff_secret_key(client.glwe_secret_key(), ntt);
    let mut message = PolynomialOwned::zero(N);
    message.as_mut()[0] = 1;
    message.as_mut()[N - 1] = 2;
    // A nontrivial encrypted mask exercises all GGSW rows through external product.
    let input = output_key
        .encrypt_message(&message, &glwe, PlaintextEmbedding::Unsigned, ntt, &mut rng)
        .into_coeff_form(ntt);
    let size = context.parameters().blind_rotation_params().size();
    let mut external_product = NttGlweExternalProductWorkspace::new(size);
    let mut control = NttGgsw::<Vec<u32>>::zero(size.ggsw_len());
    let mut product = GlweCiphertext::<Vec<u32>>::zero(size.glwe_len());
    let mut product_ntt = NttGlwe::<Vec<u32>>::zero(size.glwe_len());
    let mut decoded = PolynomialOwned::zero(N);

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
        assert_eq!(key.cipher_modulus(), Some(Q));
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
                ciphertext.write_ntt_form(&mut control, ntt);
                control.external_product_to(
                    &input,
                    &mut product,
                    key.basis(),
                    glwe.cipher_modulus(),
                    ntt,
                    &mut external_product,
                );
                product.write_ntt_form(&mut product_ntt, ntt);
                output_key.decrypt_message_to(&product_ntt, &mut decoded, &glwe, ntt);
                let bit = decoded.as_ref()[0];
                assert!(bit <= 1);
                for (&actual, &expected) in decoded.as_ref().iter().zip(message.as_ref()) {
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
fn sparse_key_rejects_invalid_parameters_and_actual_secret_before_sampling() {
    let distribution = SecretKeyDistr::fixed_hamming_weight_binary(16, 4);
    let (context_parameters, context) = self::context(distribution);

    let client = ClientKey::generate(context.parameters(), &mut StdRng::seed_from_u64(42));
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

    let invalid_cbs = primus_tfhe_glwe_ntt::CbsGadgetConfig {
        output: primus_tfhe_glwe_ntt::DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(usize::MAX)),
        },
        trace: primus_tfhe_glwe_ntt::DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        scheme_switch: primus_tfhe_glwe_ntt::DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
    };
    assert!(
        primus_tfhe_glwe::CbsGadgetParameters::try_from_config(context.parameters(), invalid_cbs,)
            .is_err()
    );

    let mut check = |client: &ClientKey<u32>,
                     copies,
                     buckets,
                     expected: primus_tfhe_glwe::KeyGenerationError| {
        let mut rng = StdRng::seed_from_u64(43);
        let result =
            generator.try_generate_sparse_blind_rotation_key(client, copies, buckets, &mut rng);
        assert_eq!(result.err(), Some(expected));
        assert_eq!(rng.next_u64(), StdRng::seed_from_u64(43).next_u64());
    };
    for (copies, buckets) in [(0, 8), (9, 8), (3, 3)] {
        check(
            &client,
            copies,
            buckets,
            Error::BucketMap(BucketMapError::InvalidBucketParameters).into(),
        );
    }
    for (copies, buckets) in [(usize::MAX, usize::MAX), (3, usize::MAX)] {
        check(&client, copies, buckets, Error::StorageSizeOverflow.into());
    }
    for coefficient in [0, 1, 2] {
        let expected = if coefficient == 2 {
            primus_tfhe_glwe::KeyGenerationError::ClientKey(
                primus_tfhe_glwe::TfheKeyError::InvalidLweSecretKeyCoefficient,
            )
        } else {
            Error::InvalidSecretCoefficients.into()
        };
        let malformed = ClientKey::new(
            LweSecretKey::new(
                vec![coefficient; 16],
                distribution,
                context.parameters().small_lwe().cipher_modulus(),
            ),
            client.glwe_secret_key().clone(),
            client.pbs_order(),
        );
        check(&malformed, 3, 8, expected);
    }
    for (distribution, expected) in [
        (
            SecretKeyDistr::UniformBinary,
            Error::UnsupportedSecretDistribution,
        ),
        (
            SecretKeyDistr::SparseTernary,
            Error::UnsupportedSecretDistribution,
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(16, 0),
            Error::InvalidHammingWeight,
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(16, 16),
            Error::InvalidHammingWeight,
        ),
    ] {
        let (_, context) = self::context(distribution);

        let mut generator = KeyGenerator::new(&context);
        let mut rng = StdRng::seed_from_u64(44);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let mut rng = StdRng::seed_from_u64(45);
        let mut expected_rng = StdRng::seed_from_u64(45);
        let result = generator.try_generate_sparse_blind_rotation_key(&client, 3, 32, &mut rng);
        assert_eq!(result.err(), Some(expected.into()));
        assert_eq!(rng.next_u64(), expected_rng.next_u64());
    }
}
