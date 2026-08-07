use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, SecretKeyDistr};
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
    GgswParameters<u32, NativeModulus<u32>>,
);

fn components() -> Components {
    let small_lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Binary,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS,
        NativeModulus::new(),
        SecretKeyDistr::Ternary,
        3.2,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
    (small_lwe, glwe, bootstrapping)
}

#[test]
fn derives_the_same_key_switching_layout_for_both_orders() {
    for order in [
        GlwePbsOrder::BootstrapKeyswitch,
        GlwePbsOrder::KeyswitchBootstrap,
    ] {
        let (small_lwe, glwe, bootstrapping) = components();
        let parameters = GlweTfheParameters::try_new(
            small_lwe,
            glwe,
            bootstrapping,
            ApproxSignedBasis::new(None, 4, Some(4)),
            order,
        )
        .unwrap();

        assert_eq!(parameters.pbs_order(), order);
        assert_eq!(
            parameters.glwe_key_switching().input_dimension(),
            GLWE_DIMENSION
        );
        assert_eq!(parameters.glwe_key_switching().output_dimension(), 1);
        assert_eq!(parameters.glwe_key_switching().poly_length(), POLY_LENGTH);
        assert_eq!(
            parameters.glwe_key_switching().output().secret_key_distr(),
            SecretKeyDistr::Binary
        );
        assert_eq!(
            parameters.glwe_key_switching().output().decompose_length(),
            4
        );
        assert_eq!(
            parameters.glwe_key_switching().output().basis().log_basis(),
            4
        );
        assert_eq!(
            parameters.ciphertext_lwe_dimension(),
            match order {
                GlwePbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
                GlwePbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
            }
        );
    }
}
