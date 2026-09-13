use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::{GadgetSize, GgswParameters, GlweCiphertext, GlweParameters, SecretKeyDistr};
use primus_lwe::{LweCiphertext, LweParameters};
use primus_modulus::NativeModulus;
use primus_poly::Polynomial;
use primus_tfhe_glwe_fourier::{
    FourierGlweBlindRotationContext, KeyGenerator, PbsOrder, TfheContext, TfheContextError,
    TfheEvaluationError, TfheParameters,
};

use rand::{Rng, SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;

fn parameters(order: PbsOrder) -> TfheParameters<u32> {
    parameters_with_bases(order, 8, 4)
}

fn parameters_with_bases(
    order: PbsOrder,
    bootstrapping_log_basis: u32,
    key_switching_log_basis: u32,
) -> TfheParameters<u32> {
    let lwe = LweParameters::new(
        4,
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        NativeModulus::new(),
        SecretKeyDistr::UniformBinary,
        0.7,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, bootstrapping_log_basis, Some(3));
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

    assert_eq!(
        error,
        TfheContextError::PolynomialLengthMismatch {
            expected: POLY_LENGTH,
            actual: POLY_LENGTH * 2,
        }
    );
}

#[test]
fn fresh_and_split_keys_support_both_pbs_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
        let context = TfheContext::try_new(parameters(order), table).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
        // The fresh pair path and the existing-client path must consume the
        // same randomness and produce compatible keys for both PBS orders.
        let mut split_rng = StdRng::seed_from_u64(42);
        let mut generator = KeyGenerator::new(&context);
        let split_client = generator.generate_client_key(&mut split_rng);
        let split_server = generator
            .try_generate_server_key(&split_client, &mut split_rng)
            .unwrap();
        assert_eq!(
            client_key.glwe_secret_key().as_slice(),
            split_client.glwe_secret_key().as_slice()
        );
        assert_eq!(
            client_key.small_lwe_secret_key().as_ref(),
            split_client.small_lwe_secret_key().as_ref()
        );
        assert_eq!(rng.next_u64(), split_rng.next_u64());
        let encryptor = context.encryptor(&client_key).unwrap();
        let decryptor = context.decryptor(&client_key).unwrap();
        let lookup_table = context.compile_lookup_table_slice(&[1u32, 0]).unwrap();
        let input = encryptor.encrypt_padded(0u32, &mut rng).unwrap();
        for server in [&server_key, &split_server] {
            let mut evaluator = context.evaluator(server).unwrap();
            let output = evaluator.apply_lookup_table(&input, &lookup_table);
            assert_eq!(decryptor.decrypt::<u32>(&output).unwrap(), 1);
        }
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
    let (_, server_key) = source.generate_keys(&mut rng).unwrap();
    for (bootstrapping_log_basis, key_switching_log_basis) in [(8, 5), (7, 4)] {
        let incompatible = TfheContext::try_new(
            parameters_with_bases(
                PbsOrder::BootstrapKeyswitch,
                bootstrapping_log_basis,
                key_switching_log_basis,
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
    let (_, server_key) = context.generate_keys(&mut rng).unwrap();
    let key = server_key.bootstrapping_key();
    let size = key.size();
    let input_len = key.input_dimension() + 1;
    let glwe_len = size.glwe_len();
    let input = LweCiphertext::new(vec![0u32; input_len]);
    let accumulator = GlweCiphertext::<Vec<u32>>::zero(glwe_len);
    let mut fft = context.new_fft_engine();
    let mut scratch = FourierGlweBlindRotationContext::new(size);

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

    // The LUT entry point also owns its per-call input/table/output checks.
    for (input_len, lookup_len, output_len) in [
        (input_len - 1, POLY_LENGTH, glwe_len),
        (input_len, POLY_LENGTH - 1, glwe_len),
        (input_len, POLY_LENGTH, glwe_len - 1),
    ] {
        let input = LweCiphertext::new(vec![0u32; input_len]);
        let lookup = Polynomial::<Vec<u32>>::zero(lookup_len);
        let mut output = GlweCiphertext::new(vec![17u32; output_len]);
        let before = output.as_ref().to_vec();
        let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            key.fourier_blind_rotate_lookup_table_to(
                &input,
                &lookup,
                &mut output,
                &mut fft,
                &mut scratch,
            );
        }));
        assert!(rejected.is_err());
        assert_eq!(output.as_ref(), before);
    }

    let wrong_table = RustFftTable::new((POLY_LENGTH * 2).trailing_zeros()).unwrap();
    let mut wrong_fft = primus_fft::FftEngine::new(&wrong_table);
    let mut wrong_scratch = FourierGlweBlindRotationContext::new(GadgetSize::new(
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
