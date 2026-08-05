//! End-to-end Fourier TFHE using key-switch-then-bootstrap order.
//!
//! These small parameters keep the example fast and are not suitable for
//! production use.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_fhe_core::{
    GgswParameters, GlweParameters, LweParameters, LweSecretKeyType, RingSecretKeyType,
};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BooleanDecryptor, BooleanEncryptor, BooleanEvaluator, PbsOrder, TfheContext, TfheParameters,
};

const LWE_DIMENSION: usize = 4;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 4;

fn parameters() -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        LweSecretKeyType::Binary,
        0.7,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        RingSecretKeyType::Binary,
        0.7,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(None, 4, Some(4)),
        PbsOrder::KeyswitchBootstrap,
    )
    .unwrap()
}

fn main() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();

    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();

    // In this order, external ciphertexts use the main GLWE key expanded as
    // an LWE key, so their dimension is kN rather than the small dimension n.
    let toggle = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    assert_eq!(input.dimension(), GLWE_DIMENSION * POLY_LENGTH);
    let output = evaluator.apply_lookup_table(&input, &toggle);
    assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);

    // The Boolean client and evaluator select the same order automatically.
    let boolean_encryptor = BooleanEncryptor::new(context.parameters(), &client_key).unwrap();
    let boolean_decryptor = BooleanDecryptor::new(context.parameters(), &client_key).unwrap();
    let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let pbs_evaluator = context.evaluator(&server_key).unwrap();
    let mut boolean_evaluator =
        BooleanEvaluator::try_new(context.parameters(), pbs_evaluator).unwrap();
    let xor = boolean_evaluator.xor(&lhs, &rhs);
    assert!(boolean_decryptor.decrypt(&xor).unwrap());

    println!("Fourier key-switch-then-bootstrap example succeeded");
}
