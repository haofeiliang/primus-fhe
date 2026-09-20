//! Experimental fixed-weight NTRU PBS. Functional parameters, not a security recommendation.

use primus_encoding::RoundedCodec;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, KeyGenerator, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const WEIGHT: usize = 32;

fn main() {
    let context = TfheContext::<_, U32NttTable>::try_from_parameters(parameters()).unwrap();
    // Public agreement: outputs use t=8 while the input uses t=16.
    let output_codec = RoundedCodec::new(8, context.parameters().external_lwe().cipher_modulus());

    // Client setup: map retries keep the same invertible client secret.
    let mut rng = StdRng::seed_from_u64(0xB802);
    let mut generator = KeyGenerator::new(&context);
    let client_key = generator.try_generate_client_key(&mut rng).unwrap();
    let server_key = generator
        .try_generate_sparse_server_key(&client_key, 3, 2 * WEIGHT, &mut rng)
        .unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let input = encryptor.encrypt_padded(7, &mut rng).unwrap();

    // Server: receive server_key and input; return message, carry and parity ciphertexts.
    let lut = context
        .parameters()
        .compile_interleaved_lookup_table_with_codec_fn(&output_codec, 3, |m, i| match i {
            0 => (m % 4) as u32,
            1 => (m / 4) as u32,
            _ => (m % 2) as u32,
        })
        .unwrap();
    let mut evaluator = context.evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); 3];
    evaluator.apply_interleaved_lookup_table_to(&input, &lut, &mut outputs);

    // Client: decode the response with the agreed output codec.
    for (output, expected) in outputs.iter().zip([3, 1, 1]) {
        let value = output_codec.decode_value(decryptor.decrypt_phase(output).unwrap());
        assert_eq!(value, expected);
    }
    println!("Sparse NTRU/NTT message, carry and parity succeeded");
}

fn parameters() -> TfheParameters<u32> {
    const DIMENSION: usize = 728;
    let modulus = BarrettModulus::new(132_120_577u32);
    let decomposition = DecompositionConfig {
        log_basis: 8,
        level_count: None,
    };
    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            DIMENSION,
            16,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, WEIGHT),
            0.7,
        ),
        poly_length: 1024,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: decomposition,
        key_switching: decomposition,
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap()
}
