use primus_decompose::primitive::ApproxSignedBasis;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    KeyGenerator, PbsOrder, TfheContext, TfheContextError, TfheEvaluationError, TfheParameters,
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
fn fresh_and_split_keys_support_both_pbs_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let modulus = BarrettModulus::new(MODULUS);
        let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
        let context = TfheContext::try_new(parameters(order), table).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
        // Validate each workflow with its own paired secrets and server key.
        let mut split_rng = StdRng::seed_from_u64(43);
        let mut generator = KeyGenerator::new(&context);
        let split_client = generator.generate_client_key(&mut split_rng);
        let split_server = generator
            .try_generate_server_key(&split_client, &mut split_rng)
            .unwrap();
        let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
        for (client, server) in [(&client_key, &server_key), (&split_client, &split_server)] {
            let public = client
                .try_generate_public_key(context.parameters(), &mut rng)
                .unwrap();
            let secret_encryptor = context.encryptor(client).unwrap();
            let public_encryptor = context.encryptor(&public).unwrap();
            let decryptor = context.decryptor(client).unwrap();
            let mut evaluator = context.evaluator(server).unwrap();
            for message in 0..2u32 {
                for input in [
                    secret_encryptor.encrypt_padded(message, &mut rng).unwrap(),
                    public_encryptor.encrypt_padded(message, &mut rng).unwrap(),
                ] {
                    let output = evaluator.apply_lookup_table(&input, &lookup_table);
                    assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1 - message);
                }
            }
            let boolean_encryptor =
                primus_tfhe_glwe_ntt::BooleanEncryptor::new(context.parameters(), &public).unwrap();
            let boolean_decryptor =
                primus_tfhe_glwe_ntt::BooleanDecryptor::new(context.parameters(), client).unwrap();
            let mut boolean_evaluator =
                primus_tfhe_glwe_ntt::BooleanEvaluator::try_new(context.parameters(), evaluator)
                    .unwrap();
            let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
            let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
            assert!(
                boolean_decryptor
                    .decrypt(&boolean_evaluator.xor(&lhs, &rhs))
                    .unwrap()
            );
        }
    }
}
