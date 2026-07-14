use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable, U64NttTable, UintNttTable};
use primus_tfhe_glwe_ntt::{TfheContext, TfheContextError, TfheParameters};

const POLY_LENGTH: usize = 256;
const MODULUS: u32 = 132_120_577;

fn parameters_u32() -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, 4, modulus, LweSecretKeyType::Binary, 0.7);
    let glwe = GlweParameters::new(1, POLY_LENGTH, 4, modulus, RingSecretKeyType::Binary, 0.7);
    let bootstrapping =
        GgswParameters::with_glwe_params(&glwe, ApproxSignedBasis::new(Some(MODULUS), 8, Some(3)));
    TfheParameters::with_key_switching_basis(
        lwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 4, Some(4)),
    )
    .unwrap()
}

#[test]
fn supports_specialized_and_generic_u32_tables() {
    let modulus = BarrettModulus::new(MODULUS);
    let specialized = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let specialized = TfheContext::try_new(parameters_u32(), specialized).unwrap();
    assert_eq!(specialized.table().modulus(), MODULUS);

    let generic = UintNttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let generic = TfheContext::try_new(parameters_u32(), generic).unwrap();
    assert_eq!(generic.table().modulus(), MODULUS);
}

#[test]
fn supports_the_specialized_u64_table() {
    let modulus_value = u64::from(MODULUS);
    let modulus = BarrettModulus::new(modulus_value);
    let lwe = LweParameters::new(4, 4, modulus, LweSecretKeyType::Binary, 0.7);
    let glwe = GlweParameters::new(1, POLY_LENGTH, 4, modulus, RingSecretKeyType::Binary, 0.7);
    let bootstrapping = GgswParameters::with_glwe_params(
        &glwe,
        ApproxSignedBasis::new(Some(modulus_value), 8, Some(3)),
    );
    let parameters = TfheParameters::with_key_switching_basis(
        lwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(modulus_value), 4, Some(4)),
    )
    .unwrap();
    let table = U64NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();

    assert!(TfheContext::try_new(parameters, table).is_ok());
}

#[test]
fn rejects_an_ntt_table_with_the_wrong_length() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new((POLY_LENGTH * 2).trailing_zeros(), modulus).unwrap();
    let error = TfheContext::try_new(parameters_u32(), table)
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

#[test]
fn rejects_an_ntt_table_with_the_wrong_modulus() {
    const OTHER_MODULUS: u32 = 998_244_353;
    let table = U32NttTable::new(
        POLY_LENGTH.trailing_zeros(),
        BarrettModulus::new(OTHER_MODULUS),
    )
    .unwrap();
    let error = TfheContext::try_new(parameters_u32(), table)
        .err()
        .expect("the mismatched table must be rejected");

    assert_eq!(
        error,
        TfheContextError::ModulusMismatch {
            expected: MODULUS,
            actual: OTHER_MODULUS,
        }
    );
}
