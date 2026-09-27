use primus_lwe::{LweParameters, LweSecretKey};
use primus_modulus::BarrettModulus;
use primus_ntru::{NlevParameters, NtruParameters, NtruSecretKey, SecretKeyDistr};
use primus_tfhe_ntru::{
    ClientKey, DecompositionConfig, TfheClientError, TfheKeyError, TfheParameters,
};

#[test]
fn imported_external_residues_must_match_the_control_domain() {
    let modulus = BarrettModulus::new(65_537u32);
    let accumulator = NtruParameters::new(8, 4, modulus, SecretKeyDistr::gaussian(3.2), 0.7);
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::UniformTernary,
    ] {
        let parameters = TfheParameters::try_new(
            LweParameters::new(4, 4, modulus, distr, 0.7),
            NlevParameters::with_ntru_params(&accumulator, 8, None),
            DecompositionConfig {
                log_basis: 8,
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
            let key = ClientKey::new(
                LweSecretKey::new(coefficients, distr),
                NtruSecretKey::new(vec![2, 1, 0, 0, 0, 0, 0, 0], SecretKeyDistr::gaussian(3.2)),
            );
            assert_eq!(key.check_compatible(&parameters).err(), error);
            assert_eq!(
                parameters.encryptor(&key).err(),
                error.clone().map(TfheClientError::IncompatibleKey)
            );
            assert_eq!(
                parameters.decryptor(&key).err(),
                error.map(TfheClientError::IncompatibleKey)
            );
        }
    }
}

#[test]
fn return_key_rejects_accumulator_magnitudes_outside_external_modulus() {
    let distr = SecretKeyDistr::gaussian(3.2);
    let accumulator = NtruParameters::new(8, 2, BarrettModulus::new(65_537u32), distr, 0.7);
    let parameters = TfheParameters::try_new(
        LweParameters::new(
            1,
            2,
            BarrettModulus::new(16),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        NlevParameters::with_ntru_params(&accumulator, 8, None),
        DecompositionConfig {
            log_basis: 2,
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
        let key = ClientKey::new(
            LweSecretKey::new(vec![1], SecretKeyDistr::UniformBinary),
            NtruSecretKey::new(vec![coefficient, 1, 0, 0, 0, 0, 0, 0], distr),
        );
        assert_eq!(key.check_compatible(&parameters).err(), expected);
    }
}
