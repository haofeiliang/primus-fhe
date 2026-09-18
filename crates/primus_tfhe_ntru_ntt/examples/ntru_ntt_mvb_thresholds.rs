//! Turn one encrypted score in 0..64 into 17 numeric threshold flags.
//! Functional cost parameters, not certified production parameters.

use primus_encoding::ScaledCodec;
use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_tfhe_ntru_ntt::{
    DecompositionConfig, InterleavedLookupTable, LookupTableError, LweCiphertext, TfheConfig,
    TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    const Q: u32 = 132_120_577;
    const N: usize = 1024;
    const DIMENSION: usize = 728;
    const DOMAIN: usize = 64;
    const OUTPUTS: usize = 17;
    let modulus = BarrettModulus::new(Q);
    let parameters = TfheParameters::try_from_config(TfheConfig {
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
    .unwrap();
    let context = TfheContext::<_, U32NttTable>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0xB302_0040);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let decryptor = context.decryptor(&client).unwrap();
    let codec = ScaledCodec::new(2, modulus);
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    let value = |score: usize, output: usize| u32::from(score >= thresholds[output]);
    let program = context
        .compile_factorized_lookup_table_fn(&codec, DOMAIN, OUTPUTS, value)
        .unwrap();

    // Interleaving 17 outputs needs 32 slots: N/32=32 positions cannot cover 64 inputs.
    assert!(matches!(
        InterleavedLookupTable::try_new(DOMAIN, N, OUTPUTS, 128, modulus, modulus, |_, _| Ok(0)),
        Err(LookupTableError::PlaintextDomainTooLarge { .. })
    ));
    let mut evaluator = context.factorized_evaluator(&server).unwrap();
    let mut input = LweCiphertext::zero(DIMENSION);
    let mut outputs = vec![LweCiphertext::zero(DIMENSION); OUTPUTS];
    for score in [12, 45] {
        encryptor
            .encrypt_padded_to(score, &mut input, &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(&input, &program, &mut outputs);
        // These Scaled numeric flags are not the Boolean evaluator's internal encoding.
        let flags: Vec<_> = outputs
            .iter()
            .map(|output| codec.decode_value(decryptor.decrypt_phase(output).unwrap()))
            .collect();
        for (i, &flag) in flags.iter().enumerate() {
            assert_eq!(flag, value(score as usize, i));
        }
        println!("score={score}, thresholds={thresholds:?}, flags={flags:?}");
    }
}
