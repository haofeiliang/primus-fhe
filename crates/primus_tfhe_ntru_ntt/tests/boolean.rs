#[path = "../../primus_tfhe/tests/support/allocations.rs"]
mod allocations;

use primus_lwe::LweParameters;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_tfhe_ntru_ntt::{
    BooleanGate, DecompositionConfig, LweCiphertext, TfheConfig, TfheContext, TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};

fn check_context() {
    let parameters = TfheParameters::<u32>::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            3,
            4,
            BarrettModulus::new(132_120_577),
            SecretKeyDistr::UniformBinary,
            0.7,
        ),
        poly_length: 256,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: 8,
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: 8,
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    let context = TfheContext::<_, U32NttTable>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0xB201);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let public = client
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.boolean_encryptor(&client).unwrap();
    let public_encryptor = context.boolean_encryptor(&public).unwrap();
    let decryptor = context.boolean_decryptor(&client).unwrap();
    let mut evaluator = context.boolean_evaluator(&server).unwrap();
    let lhs = encryptor.encrypt(true, &mut rng).unwrap();
    let mut rhs = LweCiphertext::zero(context.parameters().external_lwe_dimension());
    let mut output = rhs.clone();
    // NAND reaches both signs of the internal t=8 LUT, including its negacyclic
    // extension at 1+1. Reuse output for true -> false -> true under external t=4.
    for bit in [false, true, false] {
        let (_, allocation) = allocations::measure(|| {
            public_encryptor
                .encrypt_to(bit, &mut rhs, &mut rng)
                .unwrap();
            evaluator.evaluate_binary_to(BooleanGate::Nand, &lhs, &rhs, &mut output);
            assert_eq!(decryptor.decrypt(&output).unwrap(), !bit);
        });
        assert_eq!(allocation.count, 0, "Boolean operations must reuse storage");
    }
}

#[test]
fn boolean_binding_preserves_output_scale_and_reuses_storage() {
    check_context();
}
