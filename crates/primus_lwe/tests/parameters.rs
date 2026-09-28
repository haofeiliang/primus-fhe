use primus_lwe::{LweParameters, SecretKeyDistr};
use primus_modulus::{BarrettModulus, NativeModulus};

#[test]
fn secret_support_is_checked_at_parameter_construction() {
    for (sigma, valid) in [(1.0, true), (1.1, false)] {
        // With q = 13, truncated magnitudes 12 and 13 straddle the bound.
        let result = std::panic::catch_unwind(|| {
            LweParameters::new(
                16,
                2u32,
                BarrettModulus::new(13),
                SecretKeyDistr::gaussian(sigma),
                0.7,
            )
        });
        assert_eq!(result.is_ok(), valid);
    }
}

#[test]
fn parameters_validate_ciphertext_length() {
    for dimension in [0, usize::MAX] {
        assert_eq!(
            LweParameters::try_new(
                dimension,
                4u32,
                NativeModulus::new(),
                SecretKeyDistr::UniformBinary,
                0.7
            )
            .err(),
            Some(primus_lwe::LweParameterError::InvalidDimension)
        );
        assert!(
            std::panic::catch_unwind(|| LweParameters::new(
                dimension,
                4u32,
                NativeModulus::new(),
                SecretKeyDistr::UniformBinary,
                0.7,
            ))
            .is_err()
        );
    }
    // Parameter construction does not allocate key or ciphertext storage.
    let params = LweParameters::new(
        usize::MAX - 1,
        4u32,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    assert_eq!(params.dimension() + 1, usize::MAX);
}

#[test]
fn fallible_parameters_report_encoding_noise_and_secret_errors() {
    use primus_lwe::LweParameterError as Error;
    let make =
        |t, distr, noise| LweParameters::try_new(4, t, NativeModulus::<u32>::new(), distr, noise);
    assert!(matches!(
        make(1, SecretKeyDistr::UniformBinary, 0.7),
        Err(Error::Encoding(_))
    ));
    for noise in [0.0, f64::INFINITY, f64::NAN] {
        assert!(matches!(
            make(4, SecretKeyDistr::UniformBinary, noise),
            Err(Error::Noise(_))
        ));
    }
    for distr in [
        SecretKeyDistr::Binary {
            one_probability: -1.0,
        },
        SecretKeyDistr::FixedHammingWeightBinary { hamming_weight: 5 },
    ] {
        assert!(matches!(make(4, distr, 0.7), Err(Error::SecretKey(_))));
    }
    assert_eq!(
        LweParameters::try_new(
            4,
            2,
            BarrettModulus::new(13u32),
            SecretKeyDistr::gaussian(1.1),
            0.7
        )
        .err(),
        Some(Error::SecretKey(
            primus_distr::SecretKeySamplerError::ModulusTooSmall {
                maximum_magnitude: 13,
                modulus_minus_one: 12,
            }
        ))
    );
}
