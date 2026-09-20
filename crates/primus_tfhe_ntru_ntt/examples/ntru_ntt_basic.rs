//! Minimal complete NTRU/NTT programmable-bootstrap workflow.
//!
//! These small parameters are for demonstration only, not for production.

use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_tfhe_ntru_ntt::{DecompositionConfig, TfheConfig, TfheContext, TfheParameters};

fn main() {
    let context = TfheContext::<_, U32NttTable>::try_from_parameters(parameters()).unwrap();
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
    println!("NTRU/NTT: ordinary PBS with reused storage succeeded");
}

fn parameters() -> TfheParameters<u32> {
    const N: usize = 256;
    const LWE_DIMENSION: usize = 8;
    const Q: u32 = 132_120_577;
    let modulus = BarrettModulus::new(Q);
    let external_lwe = LweParameters::new(
        LWE_DIMENSION,
        16,
        modulus,
        SecretKeyDistr::UniformTernary,
        0.7,
    );
    TfheParameters::try_from_config(TfheConfig {
        external_lwe,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 9,
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: 9,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap()
}
