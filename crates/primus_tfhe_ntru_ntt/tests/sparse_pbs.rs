//! Classic/sparse differential PBS, ManyLUT and factorized MVB on reused workspaces;
//! bucket layouts and quantization margins are part of the fixture.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_encoding::{PlaintextEmbedding, RoundedCodec, ScaledCodec};
use primus_integer::FheUint;
use primus_lattice::LweDimension;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, SecretKeyDistr};
use primus_ntt::{MonomialNttTable, U32NttTable, U64NttTable};
use primus_poly::PolyLength;
use primus_tfhe::PbsMessageConfig;
use primus_tfhe::rotation::RotationModulusSwitch;
use primus_tfhe_ntru_ntt::{
    BlindRotationConfig, GadgetEncryptionConfig, KeyGenerator, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

// Quantizing to multiples of 4 accumulates one rounding term per nonzero mask.
// N=256 keeps the ManyLUT half-plateau wider than that error budget.
const N: usize = 256;
const DIM: usize = 16;

fn context<T: FheUint, Table: MonomialNttTable<ValueT = T>>(
    q: T,
    distr: SecretKeyDistr,
) -> TfheContext<T, Table> {
    let modulus = BarrettModulus::new(q);
    let lwe = LweParameters::new(
        LweDimension::new(DIM),
        T::as_from(16usize),
        modulus,
        distr,
        0.7,
    );

    let acc = NtruParameters::new(
        PolyLength::new(N),
        T::as_from(16usize),
        modulus,
        SecretKeyDistr::SparseTernary,
        0.7,
    );
    let blind_rotation_basis = ApproxSignedBasis::new(
        acc.cipher_modulus_value(),
        DecompositionBaseLog::new(8),
        None,
    );
    TfheContext::try_from_parameters(
        TfheParameters::try_new(
            lwe.into_encryption_parameters(),
            NlevParameters::try_with_basis(&acc, blind_rotation_basis).unwrap(),
            GadgetEncryptionConfig {
                decomposition: primus_tfhe_ntru::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
        )
        .unwrap(),
    )
    .unwrap()
}

// Independent LWE phase under the binary external secret; no backend decryption.
fn phase<T: FheUint>(cipher: &LweCiphertext<T>, secret: &[T], q: i128) -> i128 {
    let body: i128 = cipher.b().as_into();
    (body
        - cipher
            .a()
            .iter()
            .zip(secret)
            .map(|(&a, &s)| {
                let a: i128 = a.as_into();
                let s: i128 = s.as_into();
                a * s
            })
            .sum::<i128>())
    .rem_euclid(q)
}

fn check_complete<T: FheUint, Table: MonomialNttTable<ValueT = T>>(q: T, weight: usize) {
    let context = context::<T, Table>(q, SecretKeyDistr::fixed_hamming_weight_binary(DIM, weight));
    let input_codec = RoundedCodec::new(
        T::as_from(16u32),
        context.parameters().external_lwe().cipher_modulus(),
    );
    let mut rng = StdRng::seed_from_u64(0xB802);
    let mut generator = KeyGenerator::new(&context);
    let mut client = generator.try_generate_client_key(&mut rng).unwrap();
    if weight == 1 {
        // A known monomial client fixes support independently of backend/keygen RNG.
        let mut coefficients = vec![T::ZERO; DIM];
        coefficients[0] = T::ONE;
        client = primus_tfhe_ntru::ClientKey::new(
            primus_lwe::LweSecretKey::new(
                coefficients,
                context.parameters().external_lwe().secret_key_distr(),
                context.parameters().external_lwe().cipher_modulus(),
            ),
            client.accumulator_ntru_secret_key().clone(),
        );
    }
    let classic_key = generator
        .try_generate_server_key(&client, BlindRotationConfig::Classic, None, &mut rng)
        .unwrap();
    let mut classic = context.evaluator(&classic_key).unwrap();
    let modulus = context.parameters().external_lwe().cipher_modulus();
    let q_wide: i128 = q.as_into();
    let codec = RoundedCodec::new(T::as_from(8usize), modulus);
    let codecs = context
        .parameters()
        .pbs_codecs(
            PbsMessageConfig::new(input_codec.plaintext_modulus())
                .with_output_modulus(codec.plaintext_modulus()),
        )
        .unwrap();
    let compiler = context.parameters().lookup_table_compiler(&codecs).unwrap();
    let value = |m: usize, i: usize| T::as_from((m + 2 * i) % 8);
    let single = compiler.compile_fn(|m| value(m, 0)).unwrap();
    let many = compiler.compile_interleaved_fn(3, value).unwrap();
    let mut output = LweCiphertext::zero(DIM);
    let mut reference = output.clone();
    let mut outputs = vec![output.clone(); 3];

    // Integer differences in the public factors amplify BR noise. Seventeen
    // outputs also cross two complete return tiles and their singleton tail.
    let scaled = ScaledCodec::new(T::as_from(8usize), modulus);
    let mvb_codecs = context
        .parameters()
        .factorized_pbs_codecs(
            PbsMessageConfig::new(input_codec.plaintext_modulus())
                .with_output_modulus(scaled.plaintext_modulus()),
        )
        .unwrap();
    let factorized_lut = context
        .compile_factorized_lookup_table_fn(&mvb_codecs, 8, 17, value)
        .unwrap();
    let mut classic_mvb = primus_tfhe_ntru_ntt::FactorizedEvaluator::new(&classic);
    let mut factor_outputs = vec![output.clone(); 17];
    let mut factor_references = factor_outputs.clone();

    // Odd/even bucket counts exercise ownership swaps; b>n guarantees public empty buckets.
    let cases: &[(usize, usize, u64)] = if weight == 1 {
        // Seeds 1/0/37 give an empty, nonempty-unoccupied, and occupied first bucket.
        &[
            (1, 1, 0),
            (1, DIM + 1, 1),
            (1, DIM + 1, 0),
            (1, DIM + 1, 37),
        ]
    } else {
        &[(3, 8, 0xB804), (1, DIM + 1, 0xB805)]
    };
    for &(copies, buckets, seed) in cases {
        let mut key_rng = StdRng::seed_from_u64(seed);
        let server = generator
            .try_generate_server_key(
                &client,
                BlindRotationConfig::Sparse {
                    copy_count: copies,
                    bucket_count: buckets,
                },
                None,
                &mut key_rng,
            )
            .unwrap();
        assert!(server.blind_rotation_key().classic_controls().is_none());
        assert!(server.circuit_bootstrap_key().is_none());
        let key = server
            .blind_rotation_key()
            .sparse_bootstrapping_key()
            .unwrap();
        if weight == 1 {
            let (indices, controls) = key.first_bucket();
            assert_eq!(controls.count(), indices.len() + 1);
            assert_eq!(indices.is_empty(), buckets > 1 && seed == 1);
            assert_eq!(indices.contains(&0), buckets == 1 || seed == 37);
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| key.ngsw_bucket(0))).is_err()
        );
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| key.ngsw_bucket(buckets)))
                .is_err()
        );
        let mut sparse = context.evaluator(&server).unwrap();
        let mut sparse_mvb = primus_tfhe_ntru_ntt::FactorizedEvaluator::new(&sparse);
        for (message, zero_mask) in [(0, true), (3, false), (7, false), (1, true)] {
            let mut input = context
                .encryptor(client.external_lwe_secret_key(), &input_codec)
                .unwrap()
                .encrypt_padded(T::as_from(message), &mut rng)
                .unwrap();
            if zero_mask {
                input.a_mut().fill(T::ZERO);
                *input.b_mut() =
                    input_codec.encode_value(T::as_from(message), PlaintextEmbedding::Unsigned);
            }
            sparse_mvb.apply_lookup_table_to(
                input.as_view(),
                &factorized_lut,
                &mut factor_outputs,
                &mut sparse,
            );
            classic_mvb.apply_lookup_table_to(
                input.as_view(),
                &factorized_lut,
                &mut factor_references,
                &mut classic,
            );
            // Compare both paths against the function's Scaled center, not
            // against each other: independent BR/KS noise need not be identical.
            for (i, (sparse_output, classic_output)) in
                factor_outputs.iter().zip(&factor_references).enumerate()
            {
                let expected = value(message, i);
                let target: i128 = scaled
                    .encode_value(expected, PlaintextEmbedding::Unsigned)
                    .as_into();
                for cipher in [sparse_output, classic_output] {
                    let actual = phase(cipher, client.external_lwe_secret_key().as_ref(), q_wide);
                    let difference = (actual - target).rem_euclid(q_wide);
                    assert!(difference.min(q_wide - difference) < q_wide / 64);
                    assert_eq!(scaled.decode_value(T::as_from(actual)), expected);
                }
            }
            // Ordinary PBS/ManyLUT must still work after borrowing the shared
            // accumulator and return buffers for MVB.
            sparse.apply_lookup_table_to(input.as_view(), &single, output.as_mut_view());
            classic.apply_lookup_table_to(input.as_view(), &single, reference.as_mut_view());
            for cipher in [&output, &reference] {
                assert_eq!(
                    codec.decode_value(T::as_from(phase(
                        cipher,
                        client.external_lwe_secret_key().as_ref(),
                        q_wide
                    ))),
                    value(message, 0)
                );
            }
            sparse.apply_interleaved_lookup_table_to(input.as_view(), &many, &mut outputs);
            // Derive the complete public rotation from quantized mask/body and original secret.
            let modulus_switch =
                RotationModulusSwitch::new(modulus, 2 * N, many.padded_output_count());
            let exponent = client
                .external_lwe_secret_key()
                .as_ref()
                .iter()
                .zip(input.a())
                .fold(
                    (2 * N - modulus_switch.exponent(input.b())) % (2 * N),
                    |e, (&s, &a)| {
                        if s == T::ONE {
                            (e + modulus_switch.exponent(a)) % (2 * N)
                        } else {
                            e
                        }
                    },
                );
            for (i, cipher) in outputs.iter().enumerate() {
                let source = (i + 2 * N - exponent) % (2 * N);
                let target: i128 = many.polynomial().as_ref()[source % N].as_into();
                let target = if source < N { target } else { -target }.rem_euclid(q_wide);
                let actual = phase(cipher, client.external_lwe_secret_key().as_ref(), q_wide);
                let difference = (actual - target).rem_euclid(q_wide);
                assert!(difference.min(q_wide - difference) < q_wide / 64);
                assert_eq!(codec.decode_value(T::as_from(actual)), value(message, i));
            }
        }
        // A rejected call leaves outputs untouched.
        let before = outputs.clone();
        let invalid = LweCiphertext::zero(DIM - 1);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sparse.apply_interleaved_lookup_table_to(invalid.as_view(), &many, &mut outputs);
            }))
            .is_err()
        );
        assert_eq!(before, outputs);
    }
}

#[test]
fn sparse_pbs_matches_classic_outputs_and_independent_rotation() {
    for weight in [1, 4] {
        check_complete::<u32, U32NttTable>(132_120_577, weight);
        check_complete::<u64, U64NttTable>(1_125_899_906_826_241, weight);
    }
}

#[test]
fn sparse_generation_rejects_invalid_secrets_buckets_and_cbs_before_sampling() {
    use primus_ntru::NtruSecretKey;
    use primus_tfhe::sparse::BucketMapError;
    use primus_tfhe_ntru_ntt::{
        CircuitBootstrapConfig, ClientKey, DecompositionConfig, KeyGenerationError as Error,
        SparseBootstrappingKeyError as SparseError,
    };
    use rand::Rng;
    let mut rng = StdRng::seed_from_u64(0xB80201);
    for (distr, weight, expected) in [
        (
            SecretKeyDistr::UniformBinary,
            4,
            Error::SparseBootstrapping(SparseError::UnsupportedSecretDistribution),
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, 0),
            1,
            Error::SparseBootstrapping(SparseError::InvalidHammingWeight),
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, DIM),
            DIM,
            Error::SparseBootstrapping(SparseError::InvalidHammingWeight),
        ),
        (
            SecretKeyDistr::fixed_hamming_weight_binary(DIM, 4),
            3,
            Error::SparseBootstrapping(SparseError::InvalidSecretWeight),
        ),
    ] {
        let context = context::<u32, U32NttTable>(132_120_577, distr);
        let mut secret = vec![0; N];
        secret[..weight].fill(1u32);
        let mut acc = vec![0; N];
        acc[0] = 1;
        let client = ClientKey::new(
            primus_lwe::LweSecretKey::new(
                secret[..DIM].to_vec(),
                distr,
                context.parameters().external_lwe().cipher_modulus(),
            ),
            NtruSecretKey::new(acc, SecretKeyDistr::SparseTernary),
        );
        rng = StdRng::seed_from_u64(0xBAD);
        let mut untouched = StdRng::seed_from_u64(0xBAD);
        assert_eq!(
            context
                .try_generate_server_key(
                    &client,
                    BlindRotationConfig::Sparse {
                        copy_count: 3,
                        bucket_count: 8
                    },
                    None,
                    &mut rng
                )
                .err(),
            Some(expected)
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
    let context = context::<u32, U32NttTable>(
        132_120_577,
        SecretKeyDistr::fixed_hamming_weight_binary(DIM, 4),
    );
    let mut generator = KeyGenerator::new(&context);
    // Rejection paths need only the client; no BR/return key is consumed here.
    let client = generator.try_generate_client_key(&mut rng).unwrap();
    for (copies, buckets, expected) in [
        (
            0,
            8,
            SparseError::BucketMap(BucketMapError::InvalidBucketParameters),
        ),
        (
            3,
            3,
            SparseError::BucketMap(BucketMapError::InvalidBucketParameters),
        ),
        (usize::MAX, 8, SparseError::StorageSizeOverflow),
    ] {
        rng = StdRng::seed_from_u64(0xBAD);
        let mut untouched = StdRng::seed_from_u64(0xBAD);
        assert_eq!(
            generator
                .try_generate_server_key(
                    &client,
                    BlindRotationConfig::Sparse {
                        copy_count: copies,
                        bucket_count: buckets
                    },
                    None,
                    &mut rng
                )
                .err(),
            Some(Error::SparseBootstrapping(expected.clone()))
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
        rng = StdRng::seed_from_u64(0xBAD);
        let mut untouched = StdRng::seed_from_u64(0xBAD);
        assert_eq!(
            generator
                .try_generate(
                    BlindRotationConfig::Sparse {
                        copy_count: copies,
                        bucket_count: buckets
                    },
                    None,
                    &mut rng,
                )
                .err(),
            Some(Error::SparseBootstrapping(expected))
        );
        assert_eq!(rng.next_u64(), untouched.next_u64());
    }
    let noninvertible = ClientKey::new(
        client.external_lwe_secret_key().clone(),
        NtruSecretKey::new(vec![0; N], SecretKeyDistr::SparseTernary),
    );
    rng = StdRng::seed_from_u64(0xBAD);
    let mut untouched = StdRng::seed_from_u64(0xBAD);
    assert_eq!(
        generator
            .try_generate_server_key(
                &noninvertible,
                BlindRotationConfig::Sparse {
                    copy_count: 3,
                    bucket_count: 8
                },
                None,
                &mut rng
            )
            .err(),
        Some(Error::Ntru(primus_ntru::NtruError::NonInvertibleSecretKey))
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());

    // Optional CBS configuration is validated before sparse-map or key sampling.
    let decomposition = DecompositionConfig {
        log_basis: DecompositionBaseLog::new(8),
        level_count: None,
    };
    let invalid_cbs = CircuitBootstrapConfig {
        output: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: Some(DecompositionLevelCount::new(1)),
        },
        trace: GadgetEncryptionConfig {
            decomposition,
            noise_standard_deviation: -1.0,
        },
        scheme_switch: GadgetEncryptionConfig {
            decomposition,
            noise_standard_deviation: 0.7,
        },
    };
    // Fresh CBS setup must also reject the config before sampling either secret.
    let mut fresh_rng = StdRng::seed_from_u64(43);
    assert!(
        generator
            .try_generate_circuit_bootstrap_keys(
                BlindRotationConfig::Sparse {
                    copy_count: 3,
                    bucket_count: 8
                },
                invalid_cbs,
                &mut fresh_rng,
            )
            .is_err()
    );
    assert_eq!(fresh_rng.next_u64(), StdRng::seed_from_u64(43).next_u64());

    rng = StdRng::seed_from_u64(0xBAD);
    let mut untouched = StdRng::seed_from_u64(0xBAD);
    assert!(
        generator
            .try_generate_server_key(
                &client,
                BlindRotationConfig::Sparse {
                    copy_count: 3,
                    bucket_count: 8
                },
                Some(invalid_cbs),
                &mut rng
            )
            .is_err()
    );
    assert_eq!(rng.next_u64(), untouched.next_u64());
}
