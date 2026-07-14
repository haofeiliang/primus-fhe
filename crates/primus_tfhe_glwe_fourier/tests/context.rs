use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{TfheContext, TfheContextError, TfheParameters};

const POLY_LENGTH: usize = 256;

fn parameters() -> TfheParameters<u32> {
    let lwe = LweParameters::new(4, 4, NativeModulus::new(), LweSecretKeyType::Binary, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        NativeModulus::new(),
        RingSecretKeyType::Binary,
        0.7,
    );
    let bootstrapping =
        GgswParameters::with_glwe_params(&glwe, ApproxSignedBasis::new(None, 8, Some(3)));
    TfheParameters::with_key_switching_basis(
        lwe,
        bootstrapping,
        ApproxSignedBasis::new(None, 4, Some(4)),
    )
    .unwrap()
}

#[test]
fn binds_parameters_and_creates_independent_fft_engines() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();

    assert_eq!(context.parameters().glwe().poly_length(), POLY_LENGTH);
    assert_eq!(context.table().poly_length(), POLY_LENGTH);
    assert_eq!(context.new_fft_engine().poly_length(), POLY_LENGTH);
    assert_eq!(context.new_fft_engine().poly_length(), POLY_LENGTH);
}

#[test]
fn rejects_a_fourier_table_with_the_wrong_length() {
    let table = RustFftTable::new((POLY_LENGTH * 2).trailing_zeros()).unwrap();
    let error = TfheContext::try_new(parameters(), table)
        .err()
        .expect("the mismatched table must be rejected");

    assert_eq!(
        error,
        TfheContextError::PolynomialLengthMismatch {
            expected: POLY_LENGTH,
            actual: POLY_LENGTH * 2,
        }
    );
}
