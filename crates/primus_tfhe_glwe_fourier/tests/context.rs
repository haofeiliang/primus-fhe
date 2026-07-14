use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    Ciphertext, ClientKey, Decryptor, Encryptor, KeyGenerator, TfheClientError, TfheContext,
    TfheContextError, TfheKeyError, TfheParameters,
};

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
