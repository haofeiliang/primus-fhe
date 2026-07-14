use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    Ciphertext, ClientKey, Decryptor, Encryptor, Evaluator, KeyGenerator, LookupTableError,
    TfheClientError, TfheContext, TfheContextError, TfheKeyError, TfheParameters,
};

const POLY_LENGTH: usize = 256;

fn parameters() -> TfheParameters<u32> {
    parameters_with_plain_modulus(4)
}

fn parameters_with_plain_modulus(plain_modulus: u32) -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        4,
        plain_modulus,
        NativeModulus::new(),
        LweSecretKeyType::Binary,
        0.7,
    );
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        plain_modulus,
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

#[test]
fn generates_complete_client_and_server_keys() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let mut generator = KeyGenerator::new(&context);
    let mut rng = rand::rng();
    let (client_key, server_key) = generator.generate(&mut rng).unwrap();

    assert_eq!(client_key.lwe_secret_key().dimension(), 4);
    assert_eq!(client_key.glwe_secret_key().dimension(), 1);
    assert_eq!(client_key.glwe_secret_key().poly_length(), POLY_LENGTH);
    assert_eq!(server_key.bootstrapping_key().input_dimension(), 4);
    assert_eq!(
        server_key.key_switching_key().input_dimension(),
        POLY_LENGTH
    );
    assert_eq!(server_key.key_switching_key().output_dimension(), 4);

    let incompatible = ClientKey::new(
        primus_fhe_core::LweSecretKey::new(vec![0u32; 3], LweSecretKeyType::Binary),
        client_key.glwe_secret_key().clone(),
    );
    assert_eq!(
        generator
            .try_generate_server_key(&incompatible, &mut rng)
            .err(),
        Some(TfheKeyError::LweDimensionMismatch {
            expected: 4,
            actual: 3,
        })
    );
}

#[test]
fn encrypts_and_decrypts_raw_messages() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let generator = KeyGenerator::new(&context);
    let mut rng = rand::rng();
    let client_key = generator.generate_client_key(&mut rng);
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let decryptor = Decryptor::new(context.parameters(), &client_key).unwrap();

    let ciphertext = encryptor.encrypt(2u8, &mut rng).unwrap();
    assert_eq!(decryptor.decrypt::<u8>(&ciphertext).unwrap(), 2);

    // With t = 4, the canonical representative 3 denotes centered value -1.
    let ciphertext = encryptor.encrypt_centered(3u8, &mut rng).unwrap();
    assert_eq!(decryptor.decrypt::<u8>(&ciphertext).unwrap(), 3);
}

#[test]
fn rejects_invalid_client_inputs() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let generator = KeyGenerator::new(&context);
    let mut rng = rand::rng();
    let client_key = generator.generate_client_key(&mut rng);
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let decryptor = Decryptor::new(context.parameters(), &client_key).unwrap();

    assert_eq!(
        encryptor.encrypt(4u8, &mut rng).unwrap_err(),
        TfheClientError::MessageOutOfRange
    );
    assert_eq!(
        encryptor.encrypt(-1i8, &mut rng).unwrap_err(),
        TfheClientError::MessageConversion
    );
    assert!(encryptor.encrypt_padded(1u8, &mut rng).is_ok());
    assert_eq!(
        encryptor.encrypt_padded(2u8, &mut rng).unwrap_err(),
        TfheClientError::MessageOutsidePaddedDomain
    );
    assert_eq!(
        Ciphertext::try_from_lwe(primus_fhe_core::LweCiphertext::new(vec![0u32; 4]), 4)
            .unwrap_err(),
        TfheClientError::CiphertextLengthMismatch {
            expected: 5,
            actual: 4,
        }
    );
    assert_eq!(
        Ciphertext::try_from_lwe(
            primus_fhe_core::LweCiphertext::new(vec![0u32; 1]),
            usize::MAX,
        )
        .unwrap_err(),
        TfheClientError::CiphertextDimensionTooLarge
    );

    let wrong_dimension =
        Ciphertext::try_from_lwe(primus_fhe_core::LweCiphertext::new(vec![0u32; 4]), 3).unwrap();
    assert_eq!(
        decryptor.decrypt::<u8>(&wrong_dimension).unwrap_err(),
        TfheClientError::CiphertextDimensionMismatch {
            expected: 4,
            actual: 3,
        }
    );
}

#[test]
fn compiles_negacyclic_lookup_tables() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let outputs = [1u32, 2];

    let from_slice = context.compile_lookup_table_slice(&outputs).unwrap();
    let from_fn = context
        .compile_lookup_table_fn(|input| outputs[input])
        .unwrap();
    assert_eq!(
        from_slice.accumulator().as_ref(),
        from_fn.accumulator().as_ref()
    );

    let accumulator = from_slice.accumulator().as_ref();
    let body_start = context.parameters().glwe().dimension() * POLY_LENGTH;
    assert!(accumulator[..body_start].iter().all(|&value| value == 0));
    let body = &accumulator[body_start..];
    let codec = context.parameters().glwe().plaintext_codec();
    assert_eq!(codec.decode_value::<u32>(body[0]), 1);
    assert_eq!(codec.decode_value::<u32>(body[POLY_LENGTH / 2]), 2);

    for exponent in 0..(2 * POLY_LENGTH) {
        let encoded = if exponent < POLY_LENGTH {
            body[exponent]
        } else {
            body[exponent - POLY_LENGTH].wrapping_neg()
        };
        let expected = [1u32, 2, 3, 2][((exponent * 4 + POLY_LENGTH) / (2 * POLY_LENGTH)) % 4];
        assert_eq!(codec.decode_value::<u32>(encoded), expected);
    }
}

#[test]
fn validates_lookup_table_sources() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();

    context.compile_lookup_table_slice(&[0u32, 1]).unwrap();
    assert_eq!(
        context.compile_lookup_table_slice(&[1u32]).unwrap_err(),
        LookupTableError::DomainLengthMismatch {
            expected: 2,
            actual: 1,
        }
    );
    assert_eq!(
        context.compile_lookup_table_slice(&[1u32, 4]).unwrap_err(),
        LookupTableError::OutputOutOfRange { input: 1 }
    );
}

#[test]
fn supports_an_odd_message_modulus_with_one_padding_bit() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters_with_plain_modulus(10), table).unwrap();

    let lookup_table = context.compile_lookup_table_slice(&[0u32; 5]).unwrap();
    assert!(
        lookup_table
            .accumulator()
            .as_ref()
            .iter()
            .all(|&coefficient| coefficient == 0)
    );
}

#[test]
fn supports_an_odd_complete_encoding_modulus() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters_with_plain_modulus(5), table).unwrap();

    let lookup_table = context.compile_lookup_table_slice(&[1u32, 2, 3]).unwrap();
    let body_start = context.parameters().glwe().dimension() * POLY_LENGTH;
    let body = &lookup_table.accumulator().as_ref()[body_start..];
    let codec = context.parameters().glwe().plaintext_codec();
    assert_eq!(codec.decode_value::<u32>(body[0]), 1);
    assert_eq!(codec.decode_value::<u32>(body[POLY_LENGTH - 1]), 3);
}

#[test]
fn evaluates_a_complete_programmable_bootstrap_pipeline() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
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
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters_with_plain_modulus(5), table).unwrap();
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
