//! Backend Boolean integration: real PBS, encoding, rejection and evaluator reuse.

#[path = "../../primus_tfhe/tests/common/boolean.rs"]
mod boolean;

use primus_decompose::DecompositionBaseLog;
use primus_lattice::LweDimension;
use primus_modulus::BarrettModulus;
use primus_ntru::SecretKeyDistr;
use primus_ntt::U32NttTable;
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationMethod;
use primus_tfhe_ntru::{LweConfig, PbsConfig};
use primus_tfhe_ntru_ntt::{
    BooleanGate, DecompositionConfig, GadgetEncryptionConfig, LweCiphertext, PbsParameters,
    TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Reuses one key setup for gate correctness and rejected-call recovery.
fn check_context(distr: SecretKeyDistr) {
    let parameters: PbsParameters<u32> = PbsParameters::try_from_config(PbsConfig {
        external_lwe: LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: BarrettModulus::new(132_120_577).into(),
            secret_key_distr: distr,
            noise_standard_deviation: 0.7,
        },
        acc_modulus: BarrettModulus::new(132_120_577).into(),
        bsk_poly_length: PolyLength::new(32),
        bsk_secret_distr: SecretKeyDistr::SparseTernary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        algorithm: BlindRotationMethod::Classic,
        key_switching: GadgetEncryptionConfig {
            decomposition: DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: None,
            },
            noise_standard_deviation: 0.7,
        },
        messages: primus_tfhe::PbsMessageConfig::new(4),
    })
    .unwrap();
    let context_parameters = &parameters;
    let context =
        TfheContext::<_, U32NttTable>::try_from_parameters(context_parameters.clone()).unwrap();

    let mut rng = StdRng::seed_from_u64(0xB201);
    let (client, server) = context.try_generate_keys(&mut rng).unwrap();
    // Input/output choices are independent, but Boolean composition requires both t=4.
    for messages in [
        primus_tfhe::PbsMessageConfig::new(8).with_output_modulus(4),
        primus_tfhe::PbsMessageConfig::new(4).with_output_modulus(8),
    ] {
        let parameters = context.parameters().clone().with_messages(messages);
        let different = TfheContext::<_, U32NttTable>::try_from_parameters(parameters).unwrap();
        assert_eq!(
            different.boolean_evaluator(&server).err(),
            Some(primus_tfhe::TfheEvaluationError::InvalidBooleanEncoding)
        );
        if messages.input_modulus == 8 {
            assert!(
                different
                    .boolean_encryptor(client.external_lwe_secret_key())
                    .is_err()
            );
        } else {
            assert!(
                different
                    .boolean_decryptor(client.external_lwe_secret_key())
                    .is_err()
            );
        }
    }
    let public = context
        .parameters()
        .try_generate_public_key(client.external_lwe_secret_key(), &mut rng)
        .unwrap();
    let encryptor = context
        .boolean_encryptor(client.external_lwe_secret_key())
        .unwrap();
    let public_encryptor = context.boolean_public_encryptor(&public).unwrap();
    let decryptor = context
        .boolean_decryptor(client.external_lwe_secret_key())
        .unwrap();
    let mut evaluator = context.boolean_evaluator(&server).unwrap();
    let inputs = [
        encryptor.encrypt(false, &mut rng).unwrap(),
        encryptor.encrypt(true, &mut rng).unwrap(),
    ];
    let mut rhs = LweCiphertext::zero(context.parameters().external_lwe_dimension().get());
    let mut output = rhs.clone();
    let mut current = output.clone();
    boolean::check_truth_tables_and_chain(
        &mut evaluator,
        &inputs,
        &mut output,
        &mut current,
        |ciphertext| decryptor.decrypt(ciphertext.as_view()).unwrap(),
    );
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
    }
}

/// Checks binary/ternary client keys with the backend-specific ciphertext path.
#[test]
fn boolean_gates_preserve_truth_tables_chaining_and_storage() {
    for distr in [
        SecretKeyDistr::UniformBinary,
        SecretKeyDistr::fixed_composition_ternary(4, 1, 2),
    ] {
        check_context(distr);
    }
}
