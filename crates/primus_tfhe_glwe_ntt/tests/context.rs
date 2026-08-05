use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    SecretKeyDistr,
    glwe::{GgswParameters, GlweParameters},
    lwe::LweParameters,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{PbsOrder, TfheContext, TfheContextError, TfheParameters};

const POLY_LENGTH: usize = 256;
const MODULUS: u32 = 132_120_577;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, 4, modulus, SecretKeyDistr::Binary, 0.7);
    let glwe = GlweParameters::new(1, POLY_LENGTH, 4, modulus, SecretKeyDistr::Binary, 0.7);
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 4, Some(4)),
        order,
    )
    .unwrap()
}

#[test]
fn rejects_incompatible_ntt_tables() {
    let modulus = BarrettModulus::new(MODULUS);
    let wrong_length = U32NttTable::new((POLY_LENGTH * 2).trailing_zeros(), modulus).unwrap();
    let error = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), wrong_length)
        .err()
        .expect("the length mismatch must be rejected");
    assert_eq!(
        error,
        TfheContextError::PolynomialLengthMismatch {
            expected: POLY_LENGTH,
            actual: POLY_LENGTH * 2,
        }
    );

    const OTHER_MODULUS: u32 = 998_244_353;
    let wrong_modulus = U32NttTable::new(
        POLY_LENGTH.trailing_zeros(),
        BarrettModulus::new(OTHER_MODULUS),
    )
    .unwrap();
    let error = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), wrong_modulus)
        .err()
        .expect("the modulus mismatch must be rejected");
    assert_eq!(
        error,
        TfheContextError::ModulusMismatch {
            expected: MODULUS,
            actual: OTHER_MODULUS,
        }
    );
}

#[test]
fn evaluates_both_programmable_bootstrap_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let modulus = BarrettModulus::new(MODULUS);
        let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(parameters(order), table).unwrap();
        let mut rng = rand::rng();
        let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
        let encryptor = context.encryptor(&client_key).unwrap();
        let decryptor = context.decryptor(&client_key).unwrap();
        let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
        let mut evaluator = context.evaluator(&server_key).unwrap();

        let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
        let output = evaluator.apply_lookup_table(&input, &lookup_table);
        assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);
    }
}
