use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe::{DecompositionConfig, PbsOrder, TfheConfig, TfheParameters};
use std::error::Error;

const LWE_DIMENSION: usize = 630;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 1024;
const PLAIN_MODULUS: u32 = 4;

type Components = (
    LweParameters<u32, NativeModulus<u32>>,
    GlweParameters<u32, NativeModulus<u32>>,
    ApproxSignedBasis<u32>,
);

fn components() -> Components {
    let small_lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::SparseTernary,
        3.2,
    );
    let bootstrapping = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 8, Some(3));
    (small_lwe, glwe, bootstrapping)
}

#[test]
fn derives_bootstrapping_and_key_switching_for_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let (small_lwe, glwe, bootstrapping) = components();
        let expected_blind_rotation_basis = bootstrapping.clone();
        let basis = ApproxSignedBasis::new(None, 4, Some(4));
        let parameters = TfheParameters::try_from_config(TfheConfig {
            small_lwe,
            accumulator_dimension: GLWE_DIMENSION,
            poly_length: POLY_LENGTH,
            accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
            accumulator_noise_standard_deviation: 3.2,
            blind_rotation: DecompositionConfig {
                log_basis: 8,
                level_count: Some(3),
            },
            key_switching: DecompositionConfig {
                log_basis: 4,
                level_count: Some(4),
            },
            pbs_order: order,
        })
        .unwrap();
        assert!(parameters.accumulator_glwe().inner() == glwe.inner());
        assert_eq!(
            parameters.accumulator_glwe().plain_modulus_value(),
            PLAIN_MODULUS
        );

        assert_eq!(
            parameters.blind_rotation_ggsw().basis(),
            &expected_blind_rotation_basis
        );
        assert!(parameters.blind_rotation_ggsw().inner() == parameters.accumulator_glwe().inner());
        assert_eq!(
            parameters.blind_rotation_ggsw().glwe_size(),
            parameters.accumulator_glwe().size()
        );
        assert_eq!(
            parameters
                .glwe_key_switching()
                .output()
                .noise_standard_deviation(),
            parameters
                .accumulator_glwe()
                .noise_distribution()
                .standard_deviation()
        );
        assert_eq!(
            parameters.glwe_key_switching().input_dimension(),
            GLWE_DIMENSION
        );
        assert_eq!(parameters.glwe_key_switching().output_dimension(), 1);
        assert_eq!(parameters.glwe_key_switching().poly_length(), POLY_LENGTH);
        assert_eq!(
            parameters.glwe_key_switching().output().secret_key_distr(),
            SecretKeyDistr::UniformBinary
        );
        assert_eq!(parameters.glwe_key_switching().output().basis(), &basis);
        assert_eq!(
            parameters.external_lwe_dimension(),
            match order {
                PbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
                PbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
            }
        );
    }
}

#[test]
fn rejects_bases_from_another_modulus() {
    use primus_glwe::GlevParameterError::BasisModulusMismatch;
    use primus_tfhe_glwe::TfheParameterError;

    for (bsk_modulus, ksk_modulus, expected) in [
        (
            Some(257),
            None,
            TfheParameterError::BootstrappingParameters(BasisModulusMismatch),
        ),
        (
            None,
            Some(257),
            TfheParameterError::KeySwitchingParameters(BasisModulusMismatch),
        ),
    ] {
        let (small_lwe, glwe, _) = components();
        let result = TfheParameters::try_new(
            small_lwe,
            glwe,
            ApproxSignedBasis::new(bsk_modulus, 4, Some(2)),
            ApproxSignedBasis::new(ksk_modulus, 4, Some(2)),
            PbsOrder::BootstrapKeyswitch,
        );
        let error = result.err().unwrap();
        assert_eq!(error, expected);
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<primus_glwe::GlevParameterError>(),
            Some(&BasisModulusMismatch),
        );
    }
}

#[test]
fn rotation_domain_must_be_representable_by_input_coefficients() {
    use primus_tfhe_glwe::TfheParameterError;

    let modulus = NativeModulus::<u16>::new();
    for (log_n, expected) in [
        (14, None),
        (15, Some(TfheParameterError::RotationDomainTooLarge)),
        (16, Some(TfheParameterError::RotationDomainTooLarge)),
    ] {
        let small_lwe = LweParameters::new(1, 2, modulus, SecretKeyDistr::UniformBinary, 0.7);
        let glwe = GlweParameters::new(
            1,
            1 << log_n,
            2,
            modulus,
            SecretKeyDistr::UniformBinary,
            0.7,
        );
        let basis = ApproxSignedBasis::new(None, 4, None);
        assert_eq!(
            TfheParameters::try_new(
                small_lwe,
                glwe,
                basis.clone(),
                basis,
                PbsOrder::BootstrapKeyswitch,
            )
            .err(),
            expected,
        );
    }
}

fn check_ternary_padding<M: primus_reduce::RingContext<u32>>(modulus: M) {
    use primus_glwe::GlweSecretKey;
    use primus_lwe::LweSecretKey;
    use primus_tfhe_glwe::{ClientKey, TfheParameterError};

    // Five LWE coefficients occupy two length-four GLWE components.
    let glwe = GlweParameters::new(2, 4, 2, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let basis = ApproxSignedBasis::new(modulus.explicit_value(), 2, None);
    for distribution in [
        SecretKeyDistr::SparseTernary,
        SecretKeyDistr::UniformTernary,
        SecretKeyDistr::ternary(0.2, 0.5),
        SecretKeyDistr::fixed_hamming_weight_ternary(5, 4),
        SecretKeyDistr::fixed_composition_ternary(5, 2, 2),
        SecretKeyDistr::gaussian(0.7),
    ] {
        let result = TfheParameters::try_new(
            LweParameters::new(5, 2, modulus, distribution, 0.7),
            glwe.clone(),
            basis.clone(),
            basis.clone(),
            PbsOrder::BootstrapKeyswitch,
        );
        if !distribution.is_ternary() {
            assert_eq!(
                result.err(),
                Some(TfheParameterError::UnsupportedInputLweSecretKey)
            );
            continue;
        }
        let parameters = result.unwrap();
        let client = ClientKey::new(
            LweSecretKey::new(
                vec![0, 1, modulus.minus_one(), modulus.minus_one(), 1],
                distribution,
            ),
            GlweSecretKey::<u32>::new(vec![0; 8], glwe.size(), glwe.secret_key_distr()),
            parameters.pbs_order(),
        );
        client.check_compatible(&parameters).unwrap();
        let padded = client.padded_small_glwe_secret_key(&parameters);
        assert_eq!(padded.as_slice(), &[0, 1, -1, -1, 1, 0, 0, 0]);
        assert_eq!(padded.distr(), distribution);
    }
}

#[test]
fn ternary_parameters_and_padded_keys_preserve_signed_coefficients() {
    check_ternary_padding(NativeModulus::new());
    check_ternary_padding(primus_modulus::BarrettModulus::new(257));
    check_ternary_padding(primus_modulus::PowOf2Modulus::new(256));
}
