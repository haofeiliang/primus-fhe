//! GLWE/Fourier PBS and Boolean evaluation with both execution orders.
//!
//! Small functional parameters for demonstration, not production use.

use primus_encoding::RoundedCodec;
use primus_fft::RustFftTable;
use primus_glwe::SecretKeyDistr;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BooleanGate, DecompositionConfig, LweCiphertext, PbsOrder, TfheConfig, TfheContext,
    TfheParameters,
};

const LWE_DIMENSION: usize = 4;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 4;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        LWE_DIMENSION,
        PLAINTEXT_MODULUS,
        NativeModulus::new(),
        // Selects fused ternary BR; the client/evaluator API is unchanged.
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    TfheParameters::try_from_config(TfheConfig {
        small_lwe: lwe,
        accumulator_dimension: GLWE_DIMENSION,
        poly_length: POLY_LENGTH,
        accumulator_secret_key_distr: SecretKeyDistr::UniformBinary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 8,
            level_count: Some(3),
        },
        key_switching: DecompositionConfig {
            log_basis: 4,
            level_count: Some(4),
        },
        pbs_order: order,
    })
    .unwrap()
}

fn run(order: PbsOrder) {
    let context = TfheContext::<_, RustFftTable>::try_from_parameters(parameters(order)).unwrap();

    // The client key decrypts; the server key only evaluates homomorphically.
    let mut rng = rand::rng();
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();

    // Publish this LWE key to encrypt inputs; keep the client key for decryption.
    // These demonstration parameters have no public-key security/noise assessment.
    let public_key = client_key
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&public_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let toggle = context
        .parameters()
        .compile_lookup_table_slice(context.parameters().input_plaintext_codec(), &[1u32, 0])
        .unwrap();
    let mut input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
    // External inputs and outputs use n or kN according to the selected order.
    let dimension = match order {
        PbsOrder::BootstrapKeyswitch => LWE_DIMENSION,
        PbsOrder::KeyswitchBootstrap => GLWE_DIMENSION * POLY_LENGTH,
    };
    assert_eq!(input.dimension(), dimension);
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = LweCiphertext::zero(context.parameters().external_lwe_dimension());
    evaluator.apply_lookup_table_to(&input, &toggle, &mut output);
    assert_eq!(decryptor.decrypt(&output).unwrap(), 1);

    // Two functions share one PBS; input uses t=4, output uses t=8.
    let output_codec =
        RoundedCodec::new(8, context.parameters().accumulator_glwe().cipher_modulus());
    let paired = context
        .parameters()
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

    // Boolean adapters manage the internal LUT scale and restore external 0/1.
    let boolean_encryptor = context.boolean_encryptor(&public_key).unwrap();
    let boolean_decryptor = context.boolean_decryptor(&client_key).unwrap();
    let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
    let mut rhs = LweCiphertext::zero(dimension);
    boolean_encryptor
        .encrypt_to(false, &mut rhs, &mut rng)
        .unwrap();
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
