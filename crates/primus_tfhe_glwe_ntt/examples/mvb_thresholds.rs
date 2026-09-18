//! Turn one encrypted score in 0..64 into 17 numeric threshold flags.
//! Functional cost parameters, not certified production parameters.

use primus_encoding::ScaledCodec;
use primus_glwe::SecretKeyDistr;
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::BarrettModulus;
use primus_ntt::U32NttTable;
use primus_tfhe_glwe_ntt::{
    DecompositionConfig, LookupTableError, PbsOrder, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

fn main() {
    const Q: u32 = 132_120_577;
    const N: usize = 1024;
    const DOMAIN: usize = 64;
    const OUTPUTS: usize = 17;
    let modulus = BarrettModulus::new(Q);
    let parameters = TfheParameters::try_from_config(TfheConfig {
        small_lwe: LweParameters::new(
            728,
            128,
            modulus,
            SecretKeyDistr::fixed_hamming_weight_binary(728, 32),
            3.2 * f64::from(Q) / 16384.0,
        ),
        accumulator_dimension: 1,
        poly_length: N,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 6.4,
        blind_rotation: DecompositionConfig {
            log_basis: 7,
            level_count: Some(3),
        },
        key_switching: DecompositionConfig {
            log_basis: 2,
            level_count: Some(13),
        },
        pbs_order: PbsOrder::KeyswitchBootstrap,
    })
    .unwrap();
    let context = TfheContext::<_, U32NttTable>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0x4d56_4201);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let encryptor = context.encryptor(&client).unwrap();
    let decryptor = context.decryptor(&client).unwrap();
    let output_codec = ScaledCodec::new(2, modulus);
    let thresholds: Vec<_> = (1..=OUTPUTS).map(|i| i * DOMAIN / (OUTPUTS + 1)).collect();
    let function = |score: usize, output: usize| u32::from(score >= thresholds[output]);
    let lut = context
        .compile_factorized_lookup_table_fn(&output_codec, DOMAIN, OUTPUTS, function)
        .unwrap();

    // Interleaved layout needs 32 slots, leaving N/32=32 positions for 64 inputs.
    assert!(matches!(
        primus_tfhe::InterleavedLookupTable::try_new(
            DOMAIN,
            N,
            OUTPUTS,
            128,
            modulus,
            modulus,
            |_, _| Ok(0)
        ),
        Err(LookupTableError::PlaintextDomainTooLarge { .. })
    ));
    let mut evaluator = context.factorized_evaluator(&server).unwrap();
    let dimension = context.parameters().external_lwe_dimension();
    let mut input = LweCiphertext::zero(dimension);
    let mut outputs = vec![LweCiphertext::zero(dimension); OUTPUTS];
    for score in [12u32, 45] {
        encryptor
            .encrypt_padded_to(score, &mut input, &mut rng)
            .unwrap();
        evaluator.apply_lookup_table_to(&input, &lut, &mut outputs);
        // Scaled numeric 0/1 flags are not the Boolean evaluator's internal encoding.
        let flags: Vec<_> = outputs
            .iter()
            .map(|output| output_codec.decode_value(decryptor.decrypt_phase(output).unwrap()))
            .collect();
        for (i, &flag) in flags.iter().enumerate() {
            assert_eq!(flag, function(score as usize, i));
        }
        println!("score={score}, thresholds={thresholds:?}, flags={flags:?}");
    }
}
