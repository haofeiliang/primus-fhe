//! Minimal end-to-end use of the GLWE/Fourier TFHE backend.
//!
//! The small dimensions below keep the example fast. They are not a security
//! recommendation.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_fhe_core::{
    glwe::{GgswParameters, GlweParameters, RingSecretKeyType},
    lwe::{LweParameters, LweSecretKeyType},
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
        PbsOrder::BootstrapKeyswitch,
    )
    .unwrap()
}

fn main() {
    // A context binds mathematical parameters to a particular FFT table.
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();

    // The client key decrypts; the server key only evaluates homomorphically.
    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();

    // Raw programmable bootstrapping evaluates a compiled unary lookup table.
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let toggle = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
    let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let output = evaluator.apply_lookup_table(&input, &toggle);
    assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);

    // The Boolean layer uses the paper's t=4 encoding and hides its special
    // accumulator and post-PBS correction.
    let boolean_encryptor = BooleanEncryptor::new(context.parameters(), &client_key).unwrap();
    let boolean_decryptor = BooleanDecryptor::new(context.parameters(), &client_key).unwrap();
    let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let pbs_evaluator = context.evaluator(&server_key).unwrap();
    let mut boolean_evaluator =
        BooleanEvaluator::try_new(context.parameters(), pbs_evaluator).unwrap();

    let and = boolean_evaluator.and(&lhs, &rhs);
    let xor = boolean_evaluator.xor(&lhs, &rhs);
    let selected = boolean_evaluator.mux(&lhs, &xor, &and);
    assert!(!boolean_decryptor.decrypt(&and).unwrap());
    assert!(boolean_decryptor.decrypt(&xor).unwrap());
    assert!(boolean_decryptor.decrypt(&selected).unwrap());

    println!("raw PBS and Boolean Fourier examples succeeded");
}
