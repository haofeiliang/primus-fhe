use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_glwe::{GlweParameters, SecretKeyDistr};
use primus_lwe::LweParameters;
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BooleanError, LweCiphertext, PbsOrder, TfheContext, TfheParameters,
};
use primus_tfhe_test_support::boolean;
use rand::{SeedableRng, rngs::StdRng};

const POLY_LENGTH: usize = 256;

fn parameters(pbs_order: PbsOrder) -> TfheParameters<u32> {
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
    let bootstrapping = ApproxSignedBasis::new(glwe.cipher_modulus_value(), 8, Some(3));
    TfheParameters::try_new(
        lwe,
        glwe,
        bootstrapping,
        ApproxSignedBasis::new(None, 4, Some(4)),
        pbs_order,
    )
    .unwrap()
}

#[test]
fn boolean_factories_support_truth_tables_and_reused_output_in_both_orders() {
    for order in [PbsOrder::BootstrapKeyswitch, PbsOrder::KeyswitchBootstrap] {
        let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
        let context = TfheContext::try_new(parameters(order), table).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let (client_key, server_key) = context.try_generate_keys(None, &mut rng).unwrap();
        let encryptor = context.boolean_encryptor(&client_key).unwrap();
        let decryptor = context.boolean_decryptor(&client_key).unwrap();
        let mut evaluator = context.boolean_evaluator(&server_key).unwrap();
        let inputs = [
            encryptor.encrypt(false, &mut rng).unwrap(),
            encryptor.encrypt(true, &mut rng).unwrap(),
        ];
        let mut output = LweCiphertext::zero(context.parameters().external_lwe_dimension());
        encryptor.encrypt_to(false, &mut output, &mut rng).unwrap();
        assert!(!decryptor.decrypt(&output).unwrap());
        assert_eq!(
            output.dimension(),
            context.parameters().external_lwe_dimension()
        );

        let invalid = context
            .encryptor(&client_key)
            .unwrap()
            .encrypt(2, &mut rng)
            .unwrap();
        assert_eq!(
            decryptor.decrypt(&invalid),
            Err(BooleanError::InvalidPlaintext)
        );

        let mut current = output.clone();
        boolean::check_dimension_errors(&mut evaluator, &inputs[0]);
        boolean::check_truth_tables_and_chain(
            &mut evaluator,
            &inputs,
            &mut output,
            &mut current,
            |ciphertext| decryptor.decrypt(ciphertext).unwrap(),
        );
    }
}
