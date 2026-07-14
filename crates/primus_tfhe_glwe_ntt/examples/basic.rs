//! Minimal end-to-end use of the GLWE/NTT TFHE backend.
//!
//! The small dimensions below keep the example fast. They are not a security
//! recommendation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    BooleanDecryptor, BooleanEncryptor, Decryptor, Encryptor, Evaluator, KeyGenerator, TfheContext,
    TfheParameters,
};

const LWE_DIMENSION: usize = 4;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 4;
const CIPHERTEXT_MODULUS: u32 = 132_120_577;

fn parameters() -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(CIPHERTEXT_MODULUS);
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        modulus,
        LweSecretKeyType::Binary,
        0.7,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        RingSecretKeyType::Binary,
        0.7,
    );
    let bootstrapping = GgswParameters::with_glwe_params(
        &glwe,
        ApproxSignedBasis::new(Some(CIPHERTEXT_MODULUS), 8, Some(3)),
    );
    TfheParameters::with_key_switching_basis(
        lwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(CIPHERTEXT_MODULUS), 4, Some(4)),
    )
    .unwrap()
}

fn main() {
    // A context validates both the NTT length and its explicit modulus.
    let modulus = BarrettModulus::new(CIPHERTEXT_MODULUS);
    let table = U32NttTable::new(POLY_LENGTH.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();

    // The client key decrypts; the server key only evaluates homomorphically.
    let mut rng = rand::rng();
    let mut key_generator = KeyGenerator::new(&context);
    let (client_key, server_key) = key_generator.generate(&mut rng).unwrap();

    // Raw programmable bootstrapping evaluates a compiled unary lookup table.
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let decryptor = Decryptor::new(context.parameters(), &client_key).unwrap();
    let toggle = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    let mut evaluator = Evaluator::try_new(&context, &server_key).unwrap();
    let output = evaluator.apply_lookup_table(&input, &toggle).unwrap();
    assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);

    // The Boolean API is identical to the Fourier backend.
    let boolean_encryptor = BooleanEncryptor::new(context.parameters(), &client_key).unwrap();
    let boolean_decryptor = BooleanDecryptor::new(context.parameters(), &client_key).unwrap();
    let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let mut boolean_evaluator = context.new_boolean_evaluator(&server_key).unwrap();

    let and = boolean_evaluator.and(&lhs, &rhs).unwrap();
    let xor = boolean_evaluator.xor(&lhs, &rhs).unwrap();
    let selected = boolean_evaluator.mux(&lhs, &xor, &and).unwrap();
    assert!(!boolean_decryptor.decrypt(&and).unwrap());
    assert!(boolean_decryptor.decrypt(&xor).unwrap());
    assert!(boolean_decryptor.decrypt(&selected).unwrap());

    println!("raw PBS and Boolean NTT examples succeeded");
}
