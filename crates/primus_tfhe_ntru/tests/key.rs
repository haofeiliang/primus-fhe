use primus_decompose::DecompositionBaseLog;
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_lwe::LweSecretKey;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::{NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_poly::PolyLength;
use primus_tfhe_ntru::{
    ClientKey, DecompositionConfig, GadgetEncryptionConfig, PbsParameters, TfheClientError,
    TfheKeyError,
};
use rand::{RngExt, SeedableRng};

#[test]
fn imported_external_residues_must_match_the_control_domain() {
    let modulus = BarrettModulus::new(65_537u32);
    let input_codec = RoundedCodec::new(4, modulus);
    let accumulator = NtruParameters::new(
        PolyLength::new(32),
        4,
        modulus,
        SecretKeyDistr::gaussian(3.2),
        0.7,
    );
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        let parameters = PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
            external_lwe: primus_tfhe::LweConfig {
                dimension: LweDimension::new(4),
                cipher_modulus: modulus.into(),
                secret_key_distr: distr,
                noise_standard_deviation: 0.7,
            },
            acc_modulus: modulus.into(),
            bsk_poly_length: PolyLength::new(32),
            bsk_secret_distr: SecretKeyDistr::gaussian(3.2),
            bsk_gadget: GadgetEncryptionConfig {
                decomposition: primus_tfhe::DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            key_switching: GadgetEncryptionConfig {
                decomposition: DecompositionConfig {
                    log_basis: DecompositionBaseLog::new(8),
                    level_count: None,
                },
                noise_standard_deviation: 0.7,
            },
            algorithm: primus_tfhe::BlindRotationMethod::Classic,
            messages: primus_tfhe::PbsMessageConfig::new(4),
        })
        .unwrap();
        for (coefficients, error) in [
            (vec![1, 0, 1, 0], None),
            (vec![0; 4], None),
            (
                vec![2, 1, 0, 0],
                Some(TfheKeyError::InvalidClientSecretKeyCoefficient),
            ),
            (
                vec![1, 0, 65_535, 0],
                Some(TfheKeyError::InvalidClientSecretKeyCoefficient),
            ),
            (
                vec![1, 0, 65_536, 0],
                if distr.is_ternary() {
                    None
                } else {
                    Some(TfheKeyError::InvalidClientSecretKeyCoefficient)
                },
            ),
            (
                vec![1, 0, u32::MAX, 0],
                Some(TfheKeyError::InvalidClientSecretKeyCoefficient),
            ),
            (vec![1, 0], Some(TfheKeyError::ExternalLweDimensionMismatch)),
        ] {
            let mut accumulator_secret = vec![0; accumulator.poly_length().get()];
            accumulator_secret[..2].copy_from_slice(&[2, 1]);
            let key = ClientKey::new(
                LweSecretKey::new(coefficients, distr, modulus),
                NtruSecretKey::new(accumulator_secret, SecretKeyDistr::gaussian(3.2)),
            );
            assert_eq!(key.check_compatible(parameters.as_ref()).err(), error);
            assert_eq!(
                parameters
                    .as_ref()
                    .encryptor_with_codec(key.external_lwe_secret_key(), &input_codec)
                    .err(),
                error.clone().map(TfheClientError::IncompatibleKey)
            );
            assert_eq!(
                parameters
                    .as_ref()
                    .decryptor_with_codec(key.external_lwe_secret_key(), &input_codec)
                    .err(),
                error.map(TfheClientError::IncompatibleKey)
            );
        }
    }
}

#[test]
fn return_key_rejects_accumulator_magnitudes_outside_external_modulus() {
    let distr = SecretKeyDistr::gaussian(3.2);
    let accumulator = NtruParameters::new(
        PolyLength::new(32),
        2,
        BarrettModulus::new(65_537u32),
        distr,
        0.7,
    );
    let parameters = PbsParameters::try_from_config(primus_tfhe_ntru::PbsConfig {
        external_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(1),
            cipher_modulus: (PowOf2Modulus::new(16)).into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: (BarrettModulus::new(65_537u32)).into(),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: distr,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(2),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        algorithm: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(4),
    })
    .unwrap();
    for (coefficient, expected) in [
        (15, None),
        (16, Some(TfheKeyError::AccumulatorSecretOutsideLweModulus)),
        (-16, Some(TfheKeyError::AccumulatorSecretOutsideLweModulus)),
    ] {
        let mut accumulator_secret = vec![0; accumulator.poly_length().get()];
        accumulator_secret[..2].copy_from_slice(&[coefficient, 1]);
        let key = ClientKey::new(
            LweSecretKey::new(
                vec![1],
                SecretKeyDistr::UniformBinary,
                parameters.as_ref().external_lwe().cipher_modulus(),
            ),
            NtruSecretKey::new(accumulator_secret, distr),
        );
        assert_eq!(key.check_compatible(parameters.as_ref()).err(), expected);
        key.check_blind_rotation_compatible(parameters.as_ref())
            .unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(47);
        let mut untouched = rand::rngs::StdRng::seed_from_u64(47);
        assert_eq!(
            parameters.try_generate_lwe_return_key(&key, &mut rng).err(),
            expected
                .clone()
                .map(primus_tfhe_ntru::KeyGenerationError::ClientKey)
        );
        if expected.is_some() {
            assert_eq!(rng.random::<u64>(), untouched.random::<u64>());
        }
        // Return-key bounds concern setup, not ordinary external or ring clients.
        parameters
            .as_ref()
            .check_accumulator_secret_key(key.accumulator_ntru_secret_key())
            .unwrap();
        let (external, accumulator) = key.into_parts();
        drop(accumulator);
        let codec = RoundedCodec::new(2, parameters.as_ref().external_lwe().cipher_modulus());
        parameters
            .as_ref()
            .encryptor_with_codec(&external, &codec)
            .unwrap();
        parameters
            .as_ref()
            .decryptor_with_codec(&external, &codec)
            .unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(96);
        parameters
            .as_ref()
            .try_generate_public_key(&external, &mut rng)
            .unwrap();
    }
}
