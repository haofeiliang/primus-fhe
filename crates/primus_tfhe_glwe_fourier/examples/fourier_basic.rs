//! Ordinary GLWE/Fourier PBS with reusable input, output and evaluator.
//!
//! Small functional parameters for demonstration, not production use.

use primus_fft::RustFftTable;
use primus_glwe::SecretKeyDistr;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    DecompositionConfig, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};

const LWE_DIMENSION: usize = 4;
const GLWE_DIMENSION: usize = 1;
const POLY_LENGTH: usize = 256;
const PLAINTEXT_MODULUS: u32 = 16;

fn main() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        run(order);
    }
}

fn run(order: PbsOrder) {
    let context = TfheContext::<_, RustFftTable>::try_from_parameters(parameters(order)).unwrap();
    // Client setup: keep client_key local and give server_key to the server.
    let mut rng = rand::rng();
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input = context.allocate_lwe_ciphertext();

    // Server setup: public parameters, evaluation key, LUT and reusable output.
    // Input t=16 programs 0..8; outputs keep the same encoding.
    let lut = context
        .parameters()
        .compile_lookup_table_fn(|x| (x % 4) as u32)
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut output = context.allocate_lwe_ciphertext();

    for message in [7u32, 2] {
        // Client sends the encrypted input.
        encryptor
            .encrypt_padded_to(message, &mut input, &mut rng)
            .unwrap();

        // Server evaluates and returns the encrypted output.
        evaluator.apply_lookup_table_to(&input, &lut, &mut output);

        // Client decrypts the response.
        let result = decryptor.decrypt(&output).unwrap();
        assert_eq!(result, message % 4);
    }
    println!("{order:?}: ordinary PBS with reused storage succeeded");
}

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
