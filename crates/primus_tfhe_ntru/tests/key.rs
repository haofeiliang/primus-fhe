use primus_decompose::DecompositionBaseLog;
use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_lwe::LweDimension;
use primus_lwe::LweParametersInner;
use primus_lwe::LweSecretKey;
use primus_modulus::{BarrettModulus, PowOf2Modulus};
use primus_ntru::NlevParameters;
use primus_ntru::{NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_tfhe_ntru::{
    ClientKey, DecompositionConfig, TfheClientError, TfheKeyError, TfheParameters,
};
use rand::SeedableRng;

#[test]
fn imported_external_residues_must_match_the_control_domain() {
    let modulus = BarrettModulus::new(65_537u32);
    let input_codec = RoundedCodec::new(4, modulus);
    let accumulator = NtruParameters::new(32, 4, modulus, SecretKeyDistr::gaussian(3.2), 0.7);
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        let parameters = TfheParameters::try_new(
            LweParametersInner::new(LweDimension::new(4), modulus, distr, 0.7),
            NlevParameters::try_with_basis(
                &accumulator,
                ApproxSignedBasis::new(
                    accumulator.cipher_modulus_value(),
                    DecompositionBaseLog::new(8),
                    None,
                ),
            )
            .unwrap(),
            DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            0.7,
        )
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
            assert_eq!(key.check_compatible(&parameters).err(), error);
            assert_eq!(
                parameters
                    .encryptor(key.external_lwe_secret_key(), &input_codec)
                    .err(),
                error.clone().map(TfheClientError::IncompatibleKey)
            );
            assert_eq!(
                parameters
                    .decryptor(key.external_lwe_secret_key(), &input_codec)
                    .err(),
                error.map(TfheClientError::IncompatibleKey)
            );
        }
    }
}

#[test]
fn return_key_rejects_accumulator_magnitudes_outside_external_modulus() {
    let distr = SecretKeyDistr::gaussian(3.2);
    let accumulator = NtruParameters::new(32, 2, BarrettModulus::new(65_537u32), distr, 0.7);
    let parameters = TfheParameters::try_new(
        LweParametersInner::new(
            LweDimension::new(1),
            PowOf2Modulus::new(16),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::try_with_basis(
            &accumulator,
            ApproxSignedBasis::new(
                accumulator.cipher_modulus_value(),
                DecompositionBaseLog::new(8),
                None,
            ),
        )
        .unwrap(),
        DecompositionConfig {
            log_basis: DecompositionBaseLog::new(2),
            level_count: None,
        },
        0.7,
    )
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
                parameters.external_lwe().cipher_modulus(),
            ),
            NtruSecretKey::new(accumulator_secret, distr),
        );
        assert_eq!(key.check_compatible(&parameters).err(), expected);
        // Return-key bounds concern setup, not ordinary external or ring clients.
        parameters
            .check_accumulator_secret_key(key.accumulator_ntru_secret_key())
            .unwrap();
        let (external, accumulator) = key.into_parts();
        drop(accumulator);
        let codec = RoundedCodec::new(2, parameters.external_lwe().cipher_modulus());
        parameters.encryptor(&external, &codec).unwrap();
        parameters.decryptor(&external, &codec).unwrap();
        let mut rng = rand::rngs::StdRng::seed_from_u64(96);
        parameters
            .try_generate_public_key(&external, &mut rng)
            .unwrap();
    }
}
