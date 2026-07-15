use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable, U64NttTable, UintNttTable};
use primus_tfhe_glwe_ntt::{
    Decryptor, Encryptor, Evaluator, KeyGenerator, TfheClientError, TfheContext, TfheContextError,
    TfheParameters,
};

const POLY_LENGTH: usize = 256;
const MODULUS: u32 = 132_120_577;

fn parameters_u32() -> TfheParameters<u32> {
    parameters_u32_with_plain_modulus(4)
}

fn parameters_u32_with_plain_modulus(plain_modulus: u32) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(MODULUS);
    let lwe = LweParameters::new(4, plain_modulus, modulus, LweSecretKeyType::Binary, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        plain_modulus,
        modulus,
        RingSecretKeyType::Binary,
        0.7,
    );
    let bootstrapping =
        GgswParameters::with_glwe_params(&glwe, ApproxSignedBasis::new(Some(MODULUS), 8, Some(3)));
    TfheParameters::with_key_switching_basis(
        lwe,
        glwe,
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
        glwe,
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

#[test]
fn rejects_different_lwe_and_glwe_moduli_for_key_switching() {
    const LWE_MODULUS: u32 = 998_244_353;
    let lwe = LweParameters::new(
        4,
        4,
        BarrettModulus::new(LWE_MODULUS),
        LweSecretKeyType::Binary,
        0.7,
    );
    let glwe_modulus = BarrettModulus::new(MODULUS);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        glwe_modulus,
        RingSecretKeyType::Binary,
        0.7,
    );
    let bootstrapping =
        GgswParameters::with_glwe_params(&glwe, ApproxSignedBasis::new(Some(MODULUS), 8, Some(3)));
    let parameters = TfheParameters::with_key_switching_basis(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(MODULUS), 4, Some(4)),
    )
    .unwrap();
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), glwe_modulus).unwrap();

    assert_eq!(
        TfheContext::try_new(parameters, table).err(),
        Some(TfheContextError::CiphertextModulusMismatch {
            lwe: LWE_MODULUS,
            glwe: MODULUS,
        })
    );
}

#[test]
fn generates_complete_client_and_server_keys() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters_u32(), table).unwrap();
    let mut generator = KeyGenerator::new(&context);
    let mut rng = rand::rng();
    let (client_key, server_key) = generator.generate(&mut rng).unwrap();

    assert_eq!(client_key.lwe_secret_key().dimension(), 4);
    assert_eq!(client_key.glwe_secret_key().poly_length(), POLY_LENGTH);
    assert_eq!(server_key.bootstrapping_key().input_dimension(), 4);
    assert_eq!(
        server_key.key_switching_key().input_dimension(),
        POLY_LENGTH
    );
    assert_eq!(server_key.key_switching_key().output_dimension(), 4);
}

#[test]
fn encrypts_and_decrypts_raw_messages() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters_u32(), table).unwrap();
    let generator = KeyGenerator::new(&context);
    let mut rng = rand::rng();
    let client_key = generator.generate_client_key(&mut rng);
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let decryptor = Decryptor::new(context.parameters(), &client_key).unwrap();

    let ciphertext = encryptor.encrypt(2u8, &mut rng).unwrap();
    assert_eq!(decryptor.decrypt::<u8>(&ciphertext).unwrap(), 2);

    let ciphertext = encryptor.encrypt_centered(3u8, &mut rng).unwrap();
    assert_eq!(decryptor.decrypt::<u8>(&ciphertext).unwrap(), 3);
}

#[test]
fn compiles_lookup_tables_for_the_explicit_modulus() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters_u32(), table).unwrap();
    let lookup_table = context
        .compile_lookup_table_fn(|input| [1u32, 2][input])
        .unwrap();

    let accumulator = lookup_table.accumulator().as_ref();
    let body_start = context.parameters().glwe().dimension() * POLY_LENGTH;
    assert!(accumulator[..body_start].iter().all(|&value| value == 0));
    let body = &accumulator[body_start..];
    let codec = context.parameters().glwe().plaintext_codec();
    assert_eq!(codec.decode_value::<u32>(body[0]), 1);
    assert_eq!(codec.decode_value::<u32>(body[POLY_LENGTH / 2]), 2);
}

#[test]
fn evaluates_a_complete_programmable_bootstrap_pipeline() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters_u32(), table).unwrap();
    let mut rng = rand::rng();
    let mut generator = KeyGenerator::new(&context);
    let (client_key, server_key) = generator.generate(&mut rng).unwrap();
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let decryptor = Decryptor::new(context.parameters(), &client_key).unwrap();
    let lookup_table = context.compile_lookup_table_slice(&[1u32, 2]).unwrap();
    let mut evaluator = Evaluator::try_new(&context, &server_key).unwrap();

    for (input, expected) in [1u32, 2, 3, 2].into_iter().enumerate() {
        let input = encryptor.encrypt(input as u32, &mut rng).unwrap();
        let output = evaluator.apply_lookup_table(&input, &lookup_table).unwrap();
        assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), expected);
    }

    let input = encryptor.encrypt(1u32, &mut rng).unwrap();
    let mut output = input.clone();
    evaluator
        .apply_lookup_table_to(&input, &lookup_table, &mut output)
        .unwrap();
    assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 2);

    let toggle = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let mut current = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    let mut next = current.clone();
    for _ in 0..16 {
        evaluator
            .apply_lookup_table_to(&current, &toggle, &mut next)
            .unwrap();
        core::mem::swap(&mut current, &mut next);
    }
    assert_eq!(decryptor.decrypt::<u32>(&current).unwrap(), 0);
}

#[test]
fn evaluates_an_arbitrary_lookup_table_with_odd_plaintext_modulus() {
    let modulus = BarrettModulus::new(MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters_u32_with_plain_modulus(5), table).unwrap();
    let mut rng = rand::rng();
    let mut generator = KeyGenerator::new(&context);
    let (client_key, server_key) = generator.generate(&mut rng).unwrap();
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let decryptor = Decryptor::new(context.parameters(), &client_key).unwrap();
    // For odd t, the last front-half interval touches the negacyclic boundary
    // and acts as an explicit guard: -f(0) mod t = 3.
    let lookup_table = context.compile_lookup_table_slice(&[2u32, 0, 3]).unwrap();
    let mut evaluator = Evaluator::try_new(&context, &server_key).unwrap();

    for (input, expected) in [2u32, 0].into_iter().enumerate() {
        let input = encryptor.encrypt_padded(input as u32, &mut rng).unwrap();
        let output = evaluator.apply_lookup_table(&input, &lookup_table).unwrap();
        assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), expected);
    }
    assert_eq!(
        encryptor.encrypt_padded(2u32, &mut rng).unwrap_err(),
        TfheClientError::MessageOutsidePaddedDomain
    );

    let chain_lookup_table = context.compile_lookup_table_slice(&[1u32, 0, 4]).unwrap();
    let mut current = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    let mut next = current.clone();
    for _ in 0..16 {
        evaluator
            .apply_lookup_table_to(&current, &chain_lookup_table, &mut next)
            .unwrap();
        core::mem::swap(&mut current, &mut next);
    }
    assert_eq!(decryptor.decrypt::<u32>(&current).unwrap(), 0);
}
