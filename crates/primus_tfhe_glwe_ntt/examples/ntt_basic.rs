//! Minimal end-to-end use of the GLWE/NTT TFHE backend.
//!
//! The small dimensions below keep the example fast. They are not a security
//! recommendation.

use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{
    BooleanDecryptor, BooleanEncryptor, BooleanEvaluator, TfheContext, boolean_parameters,
};

fn main() {
    // A context validates both the NTT length and its explicit modulus.
    let parameters = boolean_parameters();
    let modulus = parameters.glwe().cipher_modulus();
    let poly_length = parameters.glwe().poly_length();
    let table = U32NttTable::new(poly_length.trailing_zeros(), modulus).unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();

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

    // The Boolean API is identical to the Fourier backend.
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

    println!("raw PBS and Boolean NTT examples succeeded");
}
