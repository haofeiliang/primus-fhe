use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_ntru::SecretKeyDistr;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_fourier::{
    BooleanGate, DecompositionConfig, LweCiphertext, TfheConfig, TfheContext, TfheParameters,
};
use primus_tfhe_test_support::boolean;
use rand::{SeedableRng, rngs::StdRng};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

fn check_context<Table: FftTable>() {
    let parameters = TfheParameters::<u32>::try_from_config(TfheConfig {
        external_lwe: LweParameters::new(
            3,
            4,
            NativeModulus::new(),
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
    let context = TfheContext::<_, Table>::try_from_parameters(parameters).unwrap();
    let mut rng = StdRng::seed_from_u64(0xB201);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let public = client
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.boolean_encryptor(&client).unwrap();
    let public_encryptor = context.boolean_encryptor(&public).unwrap();
    let decryptor = context.boolean_decryptor(&client).unwrap();
    let mut evaluator = context.boolean_evaluator(&server).unwrap();
    let inputs = [
        encryptor.encrypt(false, &mut rng).unwrap(),
        encryptor.encrypt(true, &mut rng).unwrap(),
    ];
    let mut rhs = LweCiphertext::zero(context.parameters().external_lwe_dimension());
    let mut output = rhs.clone();
    let mut current = output.clone();
    let (_, allocation) = allocations::measure(|| {
        boolean::check_truth_tables_and_chain(
            &mut evaluator,
            &inputs,
            &mut output,
            &mut current,
            |ciphertext| decryptor.decrypt(ciphertext).unwrap(),
        );
    });
    assert_eq!(allocation.count, 0, "Boolean gates must reuse storage");
    boolean::check_dimension_errors(&mut evaluator, &inputs[0]);

    // Keep one public-key path and confirm reuse after rejected calls.
    for bit in [false, true, false] {
        let (_, allocation) = allocations::measure(|| {
            public_encryptor
                .encrypt_to(bit, &mut rhs, &mut rng)
                .unwrap();
            evaluator.evaluate_binary_to(BooleanGate::Nand, &inputs[1], &rhs, &mut output);
            assert_eq!(decryptor.decrypt(&output).unwrap(), !bit);
        });
        assert_eq!(allocation.count, 0, "Boolean operations must reuse storage");
    }
}

#[test]
fn boolean_gates_preserve_truth_tables_chaining_and_storage() {
    check_context::<RustFftTable>();
    check_context::<TfheFftTable>();
}
