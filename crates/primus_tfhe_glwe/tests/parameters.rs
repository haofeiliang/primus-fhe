use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe::{GlwePbsOrder, GlweTfheParameters};

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
    for order in [
        GlwePbsOrder::BootstrapKeyswitch,
        GlwePbsOrder::KeyswitchBootstrap,
    ] {
        let (small_lwe, glwe, bootstrapping) = components();
        let expected_bootstrapping_basis = bootstrapping.clone();
        let basis = ApproxSignedBasis::new(None, 4, Some(4));
        let parameters =
            GlweTfheParameters::try_new(small_lwe, glwe, bootstrapping, basis.clone(), order)
                .unwrap();

        assert_eq!(
            parameters.bootstrapping().basis(),
            &expected_bootstrapping_basis
        );
        assert!(parameters.bootstrapping().inner() == parameters.glwe().inner());
        assert_eq!(
            parameters.bootstrapping().glwe_size(),
            parameters.glwe().size()
        );
        assert_eq!(
            parameters
                .glwe_key_switching()
                .output()
                .noise_standard_deviation(),
            parameters.glwe().noise_distribution().standard_deviation()
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
            parameters.ciphertext_lwe_dimension(),
            match order {
                GlwePbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
                GlwePbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
            }
        );
    }
}

#[test]
fn rejects_bases_from_another_modulus() {
    use primus_glwe::GlevParameterError::BasisModulusMismatch;
    use primus_tfhe_glwe::GlweParameterError;

    for (bsk_modulus, ksk_modulus, expected) in [
        (
            Some(257),
            None,
            GlweParameterError::BootstrappingParameters(BasisModulusMismatch),
        ),
        (
            None,
            Some(257),
            GlweParameterError::KeySwitchingParameters(BasisModulusMismatch),
        ),
    ] {
        let (small_lwe, glwe, _) = components();
        let result = GlweTfheParameters::try_new(
            small_lwe,
            glwe,
            ApproxSignedBasis::new(bsk_modulus, 4, Some(2)),
            ApproxSignedBasis::new(ksk_modulus, 4, Some(2)),
            GlwePbsOrder::BootstrapKeyswitch,
        );
        assert_eq!(result.err(), Some(expected));
    }
}
