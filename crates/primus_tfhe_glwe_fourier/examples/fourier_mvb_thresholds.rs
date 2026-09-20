//! Turn one encrypted score in 0..64 into 17 numeric threshold flags.
//! Functional cost parameters, not certified production parameters.

use primus_encoding::ScaledCodec;
use primus_fft::RustFftTable;
use primus_glwe::SecretKeyDistr;
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    DecompositionConfig, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

const DOMAIN: usize = 64;
const OUTPUTS: usize = 17;

fn main() {
    let context = TfheContext::<_, RustFftTable>::try_from_parameters(parameters()).unwrap();
    // Public agreement: thresholds and Scaled numeric flags (not Boolean gate encoding).
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    let output_codec = ScaledCodec::new(2, context.parameters().small_lwe().cipher_modulus());

    // Client setup: keep the secret and decoding workspace local.
    let mut rng = StdRng::seed_from_u64(0x4235_3401);
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
    const N: usize = 1024;
    let modulus = NativeModulus::new();
    TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            728,
            128,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * 4294967296.0 / 16384.0,
        ),
        accumulator_dimension: 1,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 6.4,
        blind_rotation: DecompositionConfig {
            log_basis: 8,
            level_count: Some(3),
        },
        key_switching: DecompositionConfig {
            log_basis: 2,
            level_count: Some(13),
        },
        pbs_order: PbsOrder::KeyswitchBootstrap,
    })
    .unwrap()
}
