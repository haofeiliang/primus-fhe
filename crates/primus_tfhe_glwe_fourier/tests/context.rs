use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::{GadgetSize, GlweCiphertext, GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe_glwe_fourier::{
    ClientKey, FourierGlweBlindRotationContext, KeyGenerator, PbsOrder, TfheContext,
    TfheContextError, TfheEvaluationError, TfheParameters,
};
use std::error::Error;

use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    parameters_with_bases(order, 8, 4, SecretKeyDistr::UniformBinary)
}

fn parameters_with_bases(
    order: PbsOrder,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
    distribution: SecretKeyDistr,
) -> TfheParameters<u32> {
    let lwe = LweParameters::new(4, 4, NativeModulus::new(), distribution, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = ApproxSignedBasis::new(
        glwe.cipher_modulus_value(),
        bootstrapping_log_basis,
        Some(3),
    );
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(None, key_switching_log_basis, Some(4)),
        order,
    )
    .unwrap()
}

#[test]
fn rejects_a_fourier_table_with_the_wrong_length() {
    let table = RustFftTable::new((POLY_LENGTH * 2).trailing_zeros()).unwrap();
    let error = TfheContext::try_new(parameters(PbsOrder::BootstrapKeyswitch), table)
        .err()
        .expect("the mismatched table must be rejected");

    assert!(matches!(error,
        TfheContextError::PolynomialLengthMismatch { expected: POLY_LENGTH, actual }
        if actual == POLY_LENGTH * 2
    ));
    // N=2 is a valid ring shape, but this FFT backend requires N >= 4.
    let tfhe = parameters(PbsOrder::BootstrapKeyswitch);
    let tiny_ring = GlweParameters::new(
        2,
        2,
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let tiny = TfheParameters::try_new(
        tfhe.small_lwe().clone(),
        tiny_ring,
        tfhe.blind_rotation_ggsw().basis().clone(),
        tfhe.glwe_key_switching().output().basis().clone(),
        PbsOrder::BootstrapKeyswitch,
    )
    .unwrap();
    let error = TfheContext::<_, RustFftTable>::try_from_parameters(tiny)
        .err()
        .unwrap();
    assert!(matches!(
        &error,
        TfheContextError::TransformTable(primus_fft::FftError::InvalidLogN { log_n: 1, .. })
    ));
    assert!(error.source().unwrap().is::<primus_fft::FftError>());
}

#[test]
fn split_keys_support_both_pbs_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
        let context = TfheContext::try_new(
            parameters_with_bases(
                order,
                8,
                4,
                SecretKeyDistr::fixed_composition_ternary(4, 1, 1),
            ),
            table,
        )
        .unwrap();
        let mut rng = StdRng::seed_from_u64(43);
        // Fresh key generation is covered by the PBS and Boolean tests.
        let mut generator = KeyGenerator::new(&context);
        let client = ClientKey::generate(context.parameters(), &mut rng);
        let server = generator
            .try_generate_server_key(&client, None, &mut rng)
            .unwrap();
        let lookup_table = context
            .parameters()
            .compile_lookup_table_slice(context.parameters().input_plaintext_codec(), &[1u32, 0])
            .unwrap();
        let public = client
            .try_generate_public_key(context.parameters(), &mut rng)
            .unwrap();
        let secret_encryptor = context.encryptor(&client).unwrap();
        let public_encryptor = context.encryptor(&public).unwrap();
        let decryptor = context.decryptor(&client).unwrap();
        let mut evaluator = context.evaluator(&server).unwrap();
        for message in 0..2u32 {
            for input in [
                secret_encryptor.encrypt_padded(message, &mut rng).unwrap(),
                public_encryptor.encrypt_padded(message, &mut rng).unwrap(),
            ] {
                let output = evaluator.apply_lookup_table(&input, &lookup_table);
                assert_eq!(decryptor.decrypt(&output).unwrap(), 1 - message);
            }
        }
        let boolean_encryptor = context.boolean_encryptor(&public).unwrap();
        let boolean_decryptor = context.boolean_decryptor(&client).unwrap();
        let mut boolean_evaluator = context.boolean_evaluator(&server).unwrap();
        let lhs = boolean_encryptor.encrypt(true, &mut rng).unwrap();
        let rhs = boolean_encryptor.encrypt(false, &mut rng).unwrap();
        assert!(
            boolean_decryptor
                .decrypt(&boolean_evaluator.xor(&lhs, &rhs))
                .unwrap()
        );
    }
}

#[test]
fn server_keys_are_bound_to_both_decomposition_bases() {
    let source = TfheContext::try_new(
        parameters(PbsOrder::BootstrapKeyswitch),
        RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, server_key) = source.try_generate_keys(None, &mut rng).unwrap();
    assert!(server_key.circuit_bootstrap_key().is_none());
    assert!(matches!(
        source.circuit_bootstrap_evaluator(&server_key),
        Err(primus_tfhe_glwe_fourier::TfheEvaluationError::MissingCircuitBootstrapKey)
    ));
    for (bootstrapping_log_basis, key_switching_log_basis, distribution) in [
        (8, 5, SecretKeyDistr::UniformBinary),
        (7, 4, SecretKeyDistr::UniformBinary),
        (8, 4, SecretKeyDistr::UniformTernary),
    ] {
        let incompatible = TfheContext::try_new(
            parameters_with_bases(
                PbsOrder::BootstrapKeyswitch,
                bootstrapping_log_basis,
                key_switching_log_basis,
                distribution,
            ),
            RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            incompatible.evaluator(&server_key),
            Err(TfheEvaluationError::IncompatibleServerKey)
        ));
    }
}

#[test]
fn public_blind_rotation_rejects_mismatches_before_output_writes() {
    let context = TfheContext::try_new(
        parameters(PbsOrder::BootstrapKeyswitch),
        RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap(),
    )
    .unwrap();
    let mut rng = StdRng::seed_from_u64(42);
    let (_, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
    let key = server_key.bootstrapping_key();
    let size = key.size();
    let input_len = key.input_dimension() + 1;
    let glwe_len = size.glwe_len();
    let input = LweCiphertext::new(vec![0u32; input_len]);
    let accumulator = GlweCiphertext::<Vec<u32>>::zero(glwe_len);
    let mut fft = context.new_fft_engine();
    let mut scratch = FourierGlweBlindRotationContext::new(key);

    // Both accumulator entry points share the same checked rotation wrapper.
    for (input_len, accumulator_len, output_len) in [
        (input_len - 1, glwe_len, glwe_len),
        (input_len, glwe_len - 1, glwe_len),
        (input_len, glwe_len, glwe_len - 1),
    ] {
        let input = LweCiphertext::new(vec![0u32; input_len]);
        let accumulator = GlweCiphertext::<Vec<u32>>::zero(accumulator_len);
        for exponents in [false, true] {
            let mut output = GlweCiphertext::new(vec![17u32; output_len]);
            let before = output.as_ref().to_vec();
            let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if exponents {
                    key.fourier_blind_rotate_exponents_to(
                        &input,
                        &accumulator,
                        &mut output,
                        &mut fft,
                        &mut scratch,
                    );
                } else {
                    key.fourier_blind_rotate_to(
                        &input,
                        &accumulator,
                        &mut output,
                        &mut fft,
                        &mut scratch,
                    );
                }
            }));
            assert!(rejected.is_err());
            assert_eq!(output.as_ref(), before);
        }
    }

    // Raw LUT APIs own their checks independently of the evaluator's metadata.
    for (input_len, lookup_len, output_len, rotation_step) in [
        (input_len - 1, POLY_LENGTH, glwe_len, None),
        (input_len, POLY_LENGTH - 1, glwe_len, None),
        (input_len, POLY_LENGTH, glwe_len - 1, None),
        (input_len - 1, POLY_LENGTH, glwe_len, Some(2)),
        (input_len, POLY_LENGTH - 1, glwe_len, Some(2)),
        (input_len, POLY_LENGTH, glwe_len - 1, Some(2)),
        (input_len, POLY_LENGTH, glwe_len, Some(0)),
        (input_len, POLY_LENGTH, glwe_len, Some(3)),
        (input_len, POLY_LENGTH, glwe_len, Some(POLY_LENGTH * 2)),
    ] {
        let input = LweCiphertext::new(vec![0u32; input_len]);
        let lookup = Polynomial::<Vec<u32>>::zero(lookup_len);
        let mut output = GlweCiphertext::new(vec![17u32; output_len]);
        let before = output.as_ref().to_vec();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(rotation_step) = rotation_step {
                key.fourier_blind_rotate_interleaved_lookup_table_to(
                    &input,
                    &lookup,
                    rotation_step,
                    &mut output,
                    &mut fft,
                    &mut scratch,
                );
            } else {
                key.fourier_blind_rotate_lookup_table_to(
                    &input,
                    &lookup,
                    &mut output,
                    &mut fft,
                    &mut scratch,
                );
            }
        }));
        assert!(rejected.is_err());
        assert_eq!(output.as_ref(), before);
    }

    let wrong_table = RustFftTable::new((POLY_LENGTH * 2).trailing_zeros()).unwrap();
    let mut wrong_fft = primus_fft::FftEngine::new(&wrong_table);
    let mut wrong_scratch = FourierGlweBlindRotationContext::new(key);
    wrong_scratch.resize(GadgetSize::new(
        size.glwe_size(),
        size.decompose_length() + 1,
    ));
    // All data have valid lengths here, so resource mismatch alone must reject.
    for (fft, scratch) in [
        (&mut wrong_fft, &mut scratch),
        (&mut fft, &mut wrong_scratch),
    ] {
        let mut output = GlweCiphertext::new(vec![17u32; glwe_len]);
        let before = output.as_ref().to_vec();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key.fourier_blind_rotate_to(&input, &accumulator, &mut output, fft, scratch);
        }));
        assert!(rejected.is_err());
        assert_eq!(output.as_ref(), before);
    }
}
