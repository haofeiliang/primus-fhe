//! Turn one encrypted score in 0..64 into 17 numeric threshold flags.
//! Functional cost parameters, not certified production parameters.

use primus_encoding::ScaledCodec;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_tfhe_ntru_ntt::{DecompositionConfig, TfheConfig, TfheContext, TfheParameters};
use rand::{SeedableRng, rngs::StdRng};

const DOMAIN: usize = 64;
const OUTPUTS: usize = 17;

fn main() {
    let context = TfheContext::<_, U32NttTable>::try_from_parameters(parameters()).unwrap();
    // Public agreement: thresholds and Scaled numeric flags (not Boolean gate encoding).
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    let output_codec = ScaledCodec::new(2, context.parameters().external_lwe().cipher_modulus());

    // Client setup: keep the secret and decoding workspace local.
    let mut rng = StdRng::seed_from_u64(0xB302_0040);
    let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client_key).unwrap();
    let decryptor = context.decryptor(&client_key).unwrap();
    let mut input = context.allocate_lwe_ciphertext();
    let mut flags = vec![0; OUTPUTS];

    // Server setup: MVB supports 64 inputs here; interleaving 17 outputs leaves only 32 input positions.
    let program = context
        .compile_factorized_lookup_table_fn(&output_codec, DOMAIN, OUTPUTS, |score, i| {
            u32::from(score >= thresholds[i])
        })
        .unwrap();
    let mut evaluator = context.factorized_evaluator(&server_key).unwrap();
    let mut outputs = vec![context.allocate_lwe_ciphertext(); OUTPUTS];

    for score in [12u32, 45] {
        // Client sends an encrypted score.
        encryptor
            .encrypt_padded_to(score, &mut input, &mut rng)
            .unwrap();

        // Server returns one encrypted flag per threshold.
        evaluator.apply_lookup_table_to(&input, &program, &mut outputs);

        // Client decodes with the agreed output codec.
        for (flag, output) in flags.iter_mut().zip(&outputs) {
            *flag = output_codec.decode_value(decryptor.decrypt_phase(output).unwrap());
        }
        for (&flag, &threshold) in flags.iter().zip(&thresholds) {
            assert_eq!(flag, u32::from(score as usize >= threshold));
        }
        println!("score={score}, thresholds={thresholds:?}, flags={flags:?}");
    }
}

fn parameters() -> TfheParameters<u32> {
    const Q: u32 = 132_120_577;
    const N: usize = 1024;
    const DIMENSION: usize = 728;
    let modulus = BarrettModulus::new(Q);
    TfheParameters::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            DIMENSION,
            128,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(DIMENSION, 32),
            3.2 * f64::from(Q) / 16384.0,
        ),
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 7,
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: 7,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap()
}
