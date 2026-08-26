use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GgswParameters, GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    PbsOrder, TfheContext, TfheContextError, TfheEvaluationError, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const MODULUS: u32 = 132_120_577;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    parameters_with_bases(order, 8, 4)
}

fn parameters_with_bases(
    order: PbsOrder,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, 4, modulus, SecretKeyDistr::UniformBinary, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, bootstrapping_log_basis, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), key_switching_log_basis, Some(4)),
        order,
    )
    .unwrap()
}

#[test]
fn server_keys_are_bound_to_their_decomposition_bases() {
    let modulus = BarrettModulus::new(MODULUS);
    let source_table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let source =
        TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), source_table).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4241_5349_534b_4559);
    let (_, server_key) = source.generate_keys(&mut rng).unwrap();

    for incompatible in [
        parameters_with_bases(PbsOrder::BootstrapKeyswitch, 7, 4),
        parameters_with_bases(PbsOrder::BootstrapKeyswitch, 8, 5),
    ] {
        let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(incompatible, table).unwrap();
        assert!(matches!(
            context.evaluator(&server_key),
            Err(TfheEvaluationError::IncompatibleServerKey)
        ));
    }
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
