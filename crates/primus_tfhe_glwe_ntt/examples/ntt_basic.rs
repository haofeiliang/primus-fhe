//! GLWE/NTT PBS and Boolean evaluation with both execution orders.
//!
//! Small functional parameters for demonstration, not production use.

use primus_decompose::primitive::ApproxSignedBasis;
use primus_encoding::RoundedCodec;
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntt::{NttTable, U32NttTable};
use primus_tfhe_glwe_ntt::{BooleanGate, LweCiphertext, PbsOrder, TfheContext, TfheParameters};

const LWE_DIMENSION: usize = 4;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 4;
const CIPHERTEXT_MODULUS: u32 = 132_120_577;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    let modulus = BarrettModulus::new(CIPHERTEXT_MODULUS);
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        modulus,
        // Selects fused ternary BR; the client/evaluator API is unchanged.
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    let glwe = GlweParameters::new(
        GLWE_DIMENSION,
        POLY_LENGTH,
        PLAINTEXT_MODULUS,
        modulus,
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 8, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(Some(CIPHERTEXT_MODULUS), 4, Some(4)),
        order,
    )
    .unwrap()
}

fn run(order: PbsOrder) {
    let parameters = parameters(order);
    let table = U32NttTable::new(
        POLY_LENGTH.trailing_zeros(),
        parameters.glwe().cipher_modulus(),
    )
    .unwrap();
    let context = TfheContext::try_new(parameters, table).unwrap();

    // The client key decrypts; the server key only evaluates homomorphically.
    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();

    // Publish this LWE key to encrypt inputs; keep the client key for decryption.
    // These demonstration parameters have no public-key security/noise assessment.
    let public_key = client_key
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&public_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let toggle = context
        .compile_lookup_table_slice(
            context.parameters().small_lwe().plaintext_codec(),
            &[1u32, 0],
        )
        .unwrap();
    let mut input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    // External inputs and outputs use n or kN according to the selected order.
    let dimension = match order {
        PbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
        PbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
    };
    assert_eq!(input.dimension(), dimension);
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = LweCiphertext::zero(context.parameters().ciphertext_lwe_dimension());
    evaluator.apply_lookup_table_to(&input, &toggle, &mut output);
    assert_eq!(decryptor.decrypt(&output).unwrap(), 1);

    // Two functions share one PBS; input uses t=4, output uses t=8.
    let output_codec = RoundedCodec::new(8, context.parameters().glwe().cipher_modulus());
    let paired = context
        .compile_interleaved_lookup_table_fn(&output_codec, 2, |input, output| {
            if output == 0 {
                (input + 4) as u32
            } else {
                (7 - input) as u32
            }
        })
        .unwrap();
    // Reuse the client ciphertext for the next input.
    encryptor
        .encrypt_padded_to(1u32, &mut input, &mut rng)
        .unwrap();
    let mut outputs = vec![output; paired.output_count()];
    evaluator.apply_interleaved_lookup_table_to(&input, &paired, &mut outputs);
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(&outputs[0]).unwrap()),
        5
    );
    assert_eq!(
        output_codec.decode_value(decryptor.decrypt_phase(&outputs[1]).unwrap()),
        6
    );

    // The Boolean API is identical to the Fourier backend.
    let boolean_encryptor = context.boolean_encryptor(&client_key).unwrap();
    let boolean_decryptor = context.boolean_decryptor(&client_key).unwrap();
    let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
    let mut boolean_evaluator = context.boolean_evaluator(&server_key).unwrap();

    let mut output = rhs.clone();
    for (gate, expected) in [(BooleanGate::And, false), (BooleanGate::Xor, true)] {
        boolean_evaluator.evaluate_binary_to(gate, &lhs, &rhs, &mut output);
        assert_eq!(boolean_decryptor.decrypt(&output).unwrap(), expected);
    }
    boolean_evaluator.not_to(&lhs, &mut output);
    assert!(!boolean_decryptor.decrypt(&output).unwrap());
    boolean_evaluator.mux_to(&lhs, &lhs, &rhs, &mut output);
    assert!(boolean_decryptor.decrypt(&output).unwrap());

    println!("{order:?}: external LWE dimension {dimension}; PBS and Boolean succeeded");
}

fn main() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        run(order);
    }
}
