//! Backend Boolean integration: real PBS, encoding, rejection and evaluator reuse.

#[path = "../../primus_tfhe/tests/common/boolean.rs"]
mod boolean;

use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::SecretKeyDistr;
use primus_lattice::{GlweDimension, LweDimension};
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe_glwe_fourier::{
    BooleanError, BooleanGate, GadgetEncryptionConfig, LweCiphertext, PbsOrder, PbsParameters,
    TfheContext,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const POLY_LENGTH: usize = 32;

/// Small parameters for client factories and both PBS orders.
fn parameters(pbs_order: PbsOrder) -> PbsParameters<u32> {
    PbsParameters::try_from_config(primus_tfhe_glwe::PbsConfig {
        small_lwe: primus_tfhe::LweConfig {
            dimension: LweDimension::new(4),
            cipher_modulus: NativeModulus::new().into(),
            secret_key_distr: SecretKeyDistr::UniformBinary,
            noise_standard_deviation: 0.7,
        },
        bsk_dimension: GlweDimension::new(1),
        bsk_poly_length: PolyLength::new(POLY_LENGTH),
        bsk_secret_distr: SecretKeyDistr::UniformBinary,
        bsk_gadget: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(8),
                level_count: Some(DecompositionLevelCount::new(3)),
            },
            noise_standard_deviation: 0.7,
        },
        key_switching: GadgetEncryptionConfig {
            decomposition: primus_tfhe::DecompositionConfig {
                log_basis: DecompositionBaseLog::new(4),
                level_count: Some(DecompositionLevelCount::new(4)),
            },
            noise_standard_deviation: 0.7,
        },
        method: primus_tfhe::BlindRotationMethod::Classic,
        messages: primus_tfhe::PbsMessageConfig::new(4),
        order: pbs_order,
    })
    .unwrap()
}

/// Checks client encoding, backend output rejection and truth tables on reused state.
#[test]
fn boolean_factories_support_truth_tables_and_reused_output_in_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
        let context_parameters = &parameters(order);
        let context = TfheContext::try_new(context_parameters.clone(), table).unwrap();
        let input_codec =
            primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
        let mut rng = StdRng::seed_from_u64(42);
        let (client_key, server_key) = context.try_generate_keys(&mut rng).unwrap();
        let encryptor = context
            .boolean_encryptor(client_key.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let decryptor = context
            .boolean_decryptor(client_key.external_lwe_secret_key(), &input_codec)
            .unwrap();
        let mut evaluator = context
            .boolean_evaluator(&server_key, &input_codec)
            .unwrap();
        let inputs = [
            encryptor.encrypt(false, &mut rng).unwrap(),
            encryptor.encrypt(true, &mut rng).unwrap(),
        ];
        let mut output = LweCiphertext::zero(context.parameters().external_lwe_dimension().get());
        encryptor
            .encrypt_to(false, output.as_mut_view(), &mut rng)
            .unwrap();
        assert!(!decryptor.decrypt(output.as_view()).unwrap());
        assert_eq!(
            output.dimension(),
            context.parameters().external_lwe_dimension().get()
        );

        let invalid = context
            .encryptor(client_key.external_lwe_secret_key())
            .unwrap()
            .encrypt(2, &mut rng)
            .unwrap();
        assert_eq!(
            decryptor.decrypt(invalid.as_view()),
            Err(BooleanError::InvalidPlaintext)
        );

        let mut current = output.clone();
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
        // Valid gates immediately reuse the evaluator after the rejected output.
        boolean::check_truth_tables_and_chain(
            &mut evaluator,
            &inputs,
            &mut output,
            &mut current,
            |ciphertext| decryptor.decrypt(ciphertext.as_view()).unwrap(),
        );
    }
}
