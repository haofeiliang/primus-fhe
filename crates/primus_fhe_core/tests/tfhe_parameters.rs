use primus_fhe_core::{
    GgswParameters, GlevParameters, GlweKeySwitchingParameters, GlweParameters, LweParameters,
    LweSecretKeyType, PbsOrder, RingSecretKeyType, TfheParameterError, TfheParameters,
};
use primus_modulus::NativeModulus;

const LWE_DIMENSION: usize = 630;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 1024;
const PLAIN_MODULUS: u32 = 4;

type Components = (
    LweParameters<u32, NativeModulus<u32>>,
    GlweParameters<u32, NativeModulus<u32>>,
    GgswParameters<u32, NativeModulus<u32>>,
    GlweKeySwitchingParameters<u32, NativeModulus<u32>>,
);

fn components() -> Components {
    let small_lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        NativeModulus::new(),
        LweSecretKeyType::Binary,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS,
        NativeModulus::new(),
        RingSecretKeyType::Ternary,
        3.2,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
    let output_glwe = GlweParameters::new(
        LWE_DIMENSION.div_ceil(POLY_LENGTH),
        POLY_LENGTH,
        PLAIN_MODULUS,
        NativeModulus::new(),
        RingSecretKeyType::Binary,
        3.2,
    );
    let output = GlevParameters::with_glwe_params(&output_glwe, 4, Some(4));
    let key_switching = GlweKeySwitchingParameters::new(GLWE_DIMENSION, output);
    (small_lwe, glwe, bootstrapping, key_switching)
}

#[test]
fn both_orders_share_the_same_glwe_key_switching_shape() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let (small_lwe, glwe, bootstrapping, key_switching) = components();
        let parameters =
            TfheParameters::try_new(small_lwe, glwe, bootstrapping, key_switching, order).unwrap();

        assert_eq!(parameters.pbs_order(), order);
        assert_eq!(
            parameters.glwe_key_switching().input_dimension(),
            GLWE_DIMENSION
        );
        assert_eq!(parameters.glwe_key_switching().output_dimension(), 1);
        assert_eq!(parameters.glwe_key_switching().poly_length(), POLY_LENGTH);
        assert_eq!(
            parameters.glwe_key_switching().output().decompose_length(),
            4
        );
        assert_eq!(parameters.blind_rotation_input_dimension(), LWE_DIMENSION);
        assert_eq!(
            parameters.ciphertext_lwe_dimension(),
            match order {
                PbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
                PbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
            }
        );

        let (_, _, _, _, actual_order) = parameters.into_parts();
        assert_eq!(actual_order, order);
    }
}

#[test]
fn derived_key_switching_layout_uses_a_binary_padded_output() {
    let (small_lwe, glwe, bootstrapping, _) = components();
    let parameters = TfheParameters::try_with_derived_glwe_key_switching(
        small_lwe,
        glwe,
        bootstrapping,
        4,
        Some(4),
        PbsOrder::BootstrapKeyswitch,
    )
    .unwrap();

    assert_eq!(parameters.pbs_order(), PbsOrder::BootstrapKeyswitch);
    assert_eq!(
        parameters.glwe_key_switching().output().secret_key_type(),
        RingSecretKeyType::Binary
    );
}

#[test]
fn rejects_invalid_glwe_key_switching_dimensions() {
    let (small_lwe, glwe, bootstrapping, key_switching) = components();
    let bad = GlweKeySwitchingParameters::new(2, key_switching.output().clone());
    assert_eq!(
        TfheParameters::try_new(
            small_lwe,
            glwe,
            bootstrapping,
            bad,
            PbsOrder::BootstrapKeyswitch,
        )
        .err()
        .unwrap(),
        TfheParameterError::GlweKeySwitchingInputDimensionMismatch {
            expected: 1,
            actual: 2,
        }
    );

    let (small_lwe, glwe, bootstrapping, _) = components();
    let output_glwe = GlweParameters::new(
        2,
        POLY_LENGTH,
        PLAIN_MODULUS,
        NativeModulus::new(),
        RingSecretKeyType::Binary,
        3.2,
    );
    let output = GlevParameters::with_glwe_params(&output_glwe, 4, Some(4));
    let bad = GlweKeySwitchingParameters::new(1, output);
    assert_eq!(
        TfheParameters::try_new(
            small_lwe,
            glwe,
            bootstrapping,
            bad,
            PbsOrder::KeyswitchBootstrap,
        )
        .err()
        .unwrap(),
        TfheParameterError::GlweKeySwitchingOutputDimensionMismatch {
            expected: 1,
            actual: 2,
        }
    );
}
