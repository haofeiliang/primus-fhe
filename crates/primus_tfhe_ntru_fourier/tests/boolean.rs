//! Backend Boolean integration: real PBS, encoding, rejection and evaluator reuse.

use primus_decompose::DecompositionBaseLog;
use primus_encoding::RoundedCodec;
use primus_fft::{FftTable, RustFftTable, TfheFftTable};
use primus_lattice::LweDimension;
use primus_lwe::LweParametersInner;
use primus_modulus::NativeModulus;
use primus_ntru::SecretKeyDistr;
use primus_test_allocations as allocations;
use primus_tfhe_ntru_fourier::{
    BooleanGate, DecompositionConfig, LweCiphertext, TfheConfig, TfheContext, TfheParameters,
};
use primus_tfhe_test_support::boolean;
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

#[global_allocator]
static ALLOCATOR: allocations::CountingAllocator = allocations::CountingAllocator;

/// Reuses one key setup for gate correctness, allocation checks and rejected-call recovery.
fn check_context<Table: FftTable>(distr: SecretKeyDistr) {
    let parameters = TfheParameters::<u32>::try_from_config(TfheConfig {
        accumulator_modulus: NativeModulus::new(),
        external_lwe: LweParametersInner::new(
            LweDimension::new(4),
            NativeModulus::new(),
            distr,
            0.7,
        ),
        poly_length: 32,
        accumulator_secret_key_distr: SecretKeyDistr::SparseTernary,
        accumulator_noise_standard_deviation: 0.7,
        blind_rotation: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        key_switching: DecompositionConfig {
            log_basis: DecompositionBaseLog::new(8),
            level_count: None,
        },
        key_switching_noise_standard_deviation: 0.7,
    })
    .unwrap();
    let context = TfheContext::<_, Table>::from_parameters(parameters);
    let input_codec = RoundedCodec::new(4, context.parameters().external_lwe().cipher_modulus());
    let mut rng = StdRng::seed_from_u64(0xB201);
    let (client, server) = context.try_generate_keys(None, &mut rng).unwrap();
    let public = client
        .try_generate_public_key(context.parameters(), &mut rng)
        .unwrap();
    let encryptor = context.boolean_encryptor(&client, &input_codec).unwrap();
    let public_encryptor = context
        .boolean_public_encryptor(&public, &input_codec)
        .unwrap();
    let decryptor = context.boolean_decryptor(&client, &input_codec).unwrap();
    let mut evaluator = context.boolean_evaluator(&server, &input_codec).unwrap();
    let inputs = [
        encryptor.encrypt(false, &mut rng).unwrap(),
        encryptor.encrypt(true, &mut rng).unwrap(),
    ];
    let mut rhs = LweCiphertext::zero(context.parameters().external_lwe_dimension().get());
    let mut output = rhs.clone();
    let mut current = output.clone();
    let (_, allocation) = allocations::measure(|| {
        boolean::check_truth_tables_and_chain(
            &mut evaluator,
            &inputs,
            &mut output,
            &mut current,
            |ciphertext| decryptor.decrypt(ciphertext.as_view()).unwrap(),
        );
    });
    assert_eq!(allocation.count, 0, "Boolean gates must reuse storage");
    // Output dimensions are checked by the real PBS backend. Common Boolean
    // input/NOT checks live in primus_tfhe/tests/boolean.rs and need no keys.
    let sentinel = LweCiphertext::new(vec![1; inputs[0].dimension()]);
    let mut wrong_output = sentinel.clone();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            evaluator.evaluate_binary_to(
                BooleanGate::And,
                inputs[0].as_view(),
                inputs[1].as_view(),
                wrong_output.as_mut_view(),
            );
        }))
        .is_err()
    );
    assert_eq!(wrong_output, sentinel);

    // Keep one public-key path and confirm reuse after rejected calls.
    for bit in [false, true, false] {
        let (_, allocation) = allocations::measure(|| {
            public_encryptor
                .encrypt_to(bit, rhs.as_mut_view(), &mut rng)
                .unwrap();
            evaluator.evaluate_binary_to(
                BooleanGate::Nand,
                inputs[1].as_view(),
                rhs.as_view(),
                output.as_mut_view(),
            );
            assert_eq!(decryptor.decrypt(output.as_view()).unwrap(), !bit);
        });
        assert_eq!(allocation.count, 0, "Boolean operations must reuse storage");
    }
}

/// Checks binary/ternary client keys with the backend-specific ciphertext path.
#[test]
fn boolean_gates_preserve_truth_tables_chaining_and_storage() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 2),
    ] {
        check_context::<RustFftTable>(distr);
        check_context::<TfheFftTable>(distr);
    }
}
