//! Backend Boolean integration: real PBS, encoding, rejection and evaluator reuse.

#[path = "../../primus_tfhe/tests/common/boolean.rs"]
mod boolean;

use primus_decompose::primitive::ApproxSignedBasis;
use primus_decompose::{DecompositionBaseLog, DecompositionLevelCount};
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lattice::{GlweDimension, LweDimension};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_poly::PolyLength;
use primus_tfhe::BlindRotationConfig;
use primus_tfhe_glwe_fourier::{
    BooleanError, BooleanGate, GadgetEncryptionConfig, LweCiphertext, PbsOrder, TfheContext,
    TfheParameters,
};
use rand::{SeedableRng, rngs::StdRng};
use std::panic::{AssertUnwindSafe, catch_unwind};

const POLY_LENGTH: usize = 32;

/// Small parameters for client factories and both PBS orders.
fn parameters(pbs_order: PbsOrder) -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        LweDimension::new(4),
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glwe = GlweParameters::new(
        GlweDimension::new(1),
        PolyLength::new(POLY_LENGTH),
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = ApproxSignedBasis::new(
        glwe.cipher_modulus_value(),
        DecompositionBaseLog::new(8),
        Some(DecompositionLevelCount::new(3)),
    );
    TfheParameters::try_new(
        lwe.into_encryption_parameters(),
        primus_glwe::GgswParameters::try_with_basis(&glwe, bootstrapping).unwrap(),
        GadgetEncryptionConfig {
            decomposition: ApproxSignedBasis::new(
                None,
                DecompositionBaseLog::new(4),
                Some(DecompositionLevelCount::new(4)),
            ),
            noise_standard_deviation: glwe.noise_distribution().standard_deviation(),
        },
        pbs_order,
    )
    .unwrap()
}

/// Checks client encoding, backend output rejection and truth tables on reused state.
#[test]
fn boolean_factories_support_truth_tables_and_reused_output_in_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = RustFftTable::new(PolyLength::new(POLY_LENGTH));
        let context = TfheContext::try_new(parameters(order), table).unwrap();
        let input_codec =
            primus_encoding::RoundedCodec::new(4, context.parameters().cipher_modulus());
        let mut rng = StdRng::seed_from_u64(42);
        let (client_key, server_key) = context
            .try_generate_keys(BlindRotationConfig::Classic, None, &mut rng)
            .unwrap();
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
            .encryptor(client_key.external_lwe_secret_key(), &input_codec)
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
