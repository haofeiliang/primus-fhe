use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    ClientKey, KeyGenerator, PbsOrder, TfheContext, TfheContextError, TfheEvaluationError,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;
const MODULUS: u32 = 132_120_577;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    parameters_with_bases(order, 8, 4, SecretKeyDistr::UniformBinary)
}

fn parameters_with_bases(
    order: PbsOrder,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
    distribution: SecretKeyDistr,
) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, 4, modulus, distribution, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = ApproxSignedBasis::new(
        glwe.cipher_modulus_value(),
        bootstrapping_log_basis,
        Some(3),
    );
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
    let (_, server_key) = source.try_generate_keys(None, &mut rng).unwrap();
    assert!(server_key.circuit_bootstrap_key().is_none());
    assert!(matches!(
        source.circuit_bootstrap_evaluator(&server_key),
        Err(primus_tfhe_glwe_ntt::TfheEvaluationError::MissingCircuitBootstrapKey)
    ));

    for incompatible in [
        parameters_with_bases(
            PbsOrder::BootstrapKeyswitch,
            7,
            4,
            SecretKeyDistr::UniformBinary,
        ),
        parameters_with_bases(
            PbsOrder::BootstrapKeyswitch,
            8,
            5,
            SecretKeyDistr::UniformBinary,
        ),
        parameters_with_bases(
            PbsOrder::BootstrapKeyswitch,
            8,
            4,
            SecretKeyDistr::UniformTernary,
        ),
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
    assert!(matches!(error,
        TfheContextError::PolynomialLengthMismatch { expected: POLY_LENGTH, actual }
        if actual == POLY_LENGTH * 2
    ));

    const OTHER_MODULUS: u32 = 998_244_353;
    let wrong_modulus = U32NttTable::new(
        POLY_LENGTH.trailing_zeros(),
        BarrettModulus::new(OTHER_MODULUS),
    )
    .unwrap();
    let error = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), wrong_modulus)
        .err()
        .expect("the modulus mismatch must be rejected");
    assert!(matches!(
        error,
        TfheContextError::ModulusMismatch {
            expected: MODULUS,
            actual: OTHER_MODULUS
        }
    ));
}

#[test]
fn split_keys_support_both_pbs_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let modulus = BarrettModulus::new(MODULUS);
        let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(
            parameters_with_bases(
                order,
                8,
                4,
                SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
            ),
            table,
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(43);
        // Fresh key generation is covered by the PBS and Boolean tests.
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let server = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let lookup_table = context
            .parameters()
            .compile_lookup_table_slice(context.parameters().input_plaintext_codec(), &[1u32, 0])
            .unwrap();
        let public = client
            .try_generate_public_key(context.parameters(), &mut rng)
            .unwrap();
        let secret_encryptor = context.encryptor(&client).unwrap();
        let public_encryptor = context.encryptor(&public).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        for message in 0..2u32 {
            for input in [
                secret_encryptor.encrypt_padded(message, &mut rng).unwrap(),
                public_encryptor.encrypt_padded(message, &mut rng).unwrap(),
            ] {
                let output = evaluator.apply_lookup_table(&input, &lookup_table);
                assert_eq!(decryptor.decrypt(&output).unwrap(), 1 - message);
            }
        }
        let boolean_encryptor = context.boolean_encryptor(&public).unwrap();
        let boolean_decryptor = context.boolean_decryptor(&client).unwrap();
        let mut boolean_evaluator = context.boolean_evaluator(&server).unwrap();
        let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
        let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
        assert!(
            boolean_decryptor
                .decrypt(&boolean_evaluator.xor(&lhs, &rhs))
                .unwrap()
        );
    }
}
