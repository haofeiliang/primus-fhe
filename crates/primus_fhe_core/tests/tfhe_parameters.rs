use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweKeySwitchingParameters, LweParameters, LweSecretKeyType,
    RingSecretKeyType, TfheParameterError, TfheParameters,
};
use primus_modulus::{BarrettModulus, NativeModulus};

const LWE_DIMENSION: usize = 630;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 1024;
const PLAIN_MODULUS: u32 = 4;
const MISMATCHED_MODULUS: u32 = 16_777_217;

type NativeComponents = (
    LweParameters<u32, NativeModulus<u32>>,
    GgswParameters<u32, NativeModulus<u32>>,
    LweKeySwitchingParameters<u32>,
);

fn native_components(
    lwe_secret_key_type: LweSecretKeyType,
    glwe_plain_modulus: u32,
    bootstrapping_basis_modulus: Option<u32>,
    key_switching_input_dimension: usize,
    key_switching_output_dimension: usize,
    key_switching_basis_modulus: Option<u32>,
) -> NativeComponents {
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        NativeModulus::new(),
        lwe_secret_key_type,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        glwe_plain_modulus,
        NativeModulus::new(),
        RingSecretKeyType::Binary,
        3.2,
    );
    let bootstrapping = GgswParameters::with_glwe_params(
        &glwe,
        ApproxSignedBasis::new(bootstrapping_basis_modulus, 8, Some(3)),
    );
    let key_switching = LweKeySwitchingParameters::new(
        key_switching_input_dimension,
        key_switching_output_dimension,
        ApproxSignedBasis::new(key_switching_basis_modulus, 4, Some(4)),
    );
    (lwe, bootstrapping, key_switching)
}

#[test]
fn accepts_native_torus_parameters_and_exposes_components() {
    let (lwe, bootstrapping, _) = native_components(
        LweSecretKeyType::Binary,
        PLAIN_MODULUS,
        None,
        GLWE_DIMENSION * POLY_LENGTH,
        LWE_DIMENSION,
        None,
    );

    let parameters = TfheParameters::with_key_switching_basis(
        lwe,
        bootstrapping,
        ApproxSignedBasis::new(None, 4, Some(4)),
    )
    .unwrap();

    assert_eq!(parameters.lwe().dimension(), LWE_DIMENSION);
    assert_eq!(parameters.glwe().dimension(), GLWE_DIMENSION);
    assert_eq!(parameters.glwe().poly_length(), POLY_LENGTH);
    assert_eq!(parameters.plain_modulus_value(), PLAIN_MODULUS);
    assert_eq!(parameters.key_switching().decompose_length(), 4);

    let (lwe, bootstrapping, key_switching) = parameters.into_parts();
    assert_eq!(lwe.dimension(), LWE_DIMENSION);
    assert_eq!(bootstrapping.poly_length(), POLY_LENGTH);
    assert_eq!(key_switching.input_dimension(), POLY_LENGTH);
}

#[test]
fn accepts_explicit_modulus_parameters() {
    const MODULUS: u32 = 132_120_577;
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAIN_MODULUS,
        modulus,
        LweSecretKeyType::Binary,
        3.2,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAIN_MODULUS,
        modulus,
        RingSecretKeyType::Ternary,
        3.2,
    );
    let bootstrapping =
        GgswParameters::with_glwe_params(&glwe, ApproxSignedBasis::new(Some(MODULUS), 8, Some(3)));
    let key_switching = LweKeySwitchingParameters::new(
        GLWE_DIMENSION * POLY_LENGTH,
        LWE_DIMENSION,
        ApproxSignedBasis::new(Some(MODULUS), 4, Some(4)),
    );

    assert!(TfheParameters::try_new(lwe, bootstrapping, key_switching).is_ok());
}

#[test]
fn rejects_incompatible_component_parameters() {
    let cases = [
        (
            native_components(
                LweSecretKeyType::Ternary,
                PLAIN_MODULUS,
                None,
                POLY_LENGTH,
                LWE_DIMENSION,
                None,
            ),
            TfheParameterError::InputLweSecretKeyMustBeBinary,
        ),
        (
            native_components(
                LweSecretKeyType::Binary,
                PLAIN_MODULUS * 2,
                None,
                POLY_LENGTH,
                LWE_DIMENSION,
                None,
            ),
            TfheParameterError::PlainModulusMismatch,
        ),
        (
            native_components(
                LweSecretKeyType::Binary,
                PLAIN_MODULUS,
                Some(MISMATCHED_MODULUS),
                POLY_LENGTH,
                LWE_DIMENSION,
                None,
            ),
            TfheParameterError::BootstrappingBasisModulusMismatch,
        ),
        (
            native_components(
                LweSecretKeyType::Binary,
                PLAIN_MODULUS,
                None,
                POLY_LENGTH / 2,
                LWE_DIMENSION,
                None,
            ),
            TfheParameterError::KeySwitchingInputDimensionMismatch {
                expected: POLY_LENGTH,
                actual: POLY_LENGTH / 2,
            },
        ),
        (
            native_components(
                LweSecretKeyType::Binary,
                PLAIN_MODULUS,
                None,
                POLY_LENGTH,
                LWE_DIMENSION / 2,
                None,
            ),
            TfheParameterError::KeySwitchingOutputDimensionMismatch {
                expected: LWE_DIMENSION,
                actual: LWE_DIMENSION / 2,
            },
        ),
        (
            native_components(
                LweSecretKeyType::Binary,
                PLAIN_MODULUS,
                None,
                POLY_LENGTH,
                LWE_DIMENSION,
                Some(MISMATCHED_MODULUS),
            ),
            TfheParameterError::KeySwitchingBasisModulusMismatch,
        ),
    ];

    for ((lwe, bootstrapping, key_switching), expected) in cases {
        let actual = TfheParameters::try_new(lwe, bootstrapping, key_switching)
            .err()
            .expect("the parameter combination must be rejected");
        assert_eq!(actual, expected);
    }
}
