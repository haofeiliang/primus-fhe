//! End-to-end NTT TFHE using key-switch-then-bootstrap order.
//!
//! These small parameters keep the example fast and are not suitable for
//! production use.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    BooleanDecryptor, BooleanEncryptor, Decryptor, Encryptor, Evaluator, KeyGenerator, PbsOrder,
    TfheContext, TfheParameters,
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
    TfheParameters::with_pbs_order_and_key_switching_basis(
        lwe,
        glwe,
        bootstrapping,
        PbsOrder::KeyswitchBootstrap,
        ApproxSignedBasis::new(Some(CIPHERTEXT_MODULUS), 4, Some(4)),
    )
    .unwrap()
}

fn main() {
    let parameters = parameters();
    let table = U32NttTable::new(
        POLY_LENGTH.trailing_zeros(),
        parameters.glwe().cipher_modulus(),
    )
    .unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();

    let mut rng = rand::rng();
    let mut key_generator = KeyGenerator::new(&context);
    let (client_key, server_key) = key_generator.generate(&mut rng).unwrap();
    let encryptor = Encryptor::with_client_key(context.parameters(), &client_key).unwrap();
    let decryptor = Decryptor::new(context.parameters(), &client_key).unwrap();
    let mut evaluator = Evaluator::try_new(&context, &server_key).unwrap();

    // In this order, external ciphertexts use the main GLWE key expanded as
    // an LWE key, so their dimension is kN rather than the small dimension n.
    let toggle = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    assert_eq!(input.dimension(), GLWE_DIMENSION * POLY_LENGTH);
    let output = evaluator.apply_lookup_table(&input, &toggle).unwrap();
    assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);

    // The Boolean client and evaluator select the same order automatically.
    let boolean_encryptor = BooleanEncryptor::new(context.parameters(), &client_key).unwrap();
    let boolean_decryptor = BooleanDecryptor::new(context.parameters(), &client_key).unwrap();
    let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let mut boolean_evaluator = context.new_boolean_evaluator(&server_key).unwrap();
    let xor = boolean_evaluator.xor(&lhs, &rhs).unwrap();
    assert!(boolean_decryptor.decrypt(&xor).unwrap());

    println!("NTT key-switch-then-bootstrap example succeeded");
}
