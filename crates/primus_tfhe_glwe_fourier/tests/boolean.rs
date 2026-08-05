use primus_decompose::primitive::ApproxSignedBasis;
use primus_fft::{FftTable, RustFftTable};
use primus_fhe_core::lwe::LweParameters;
use primus_glwe::{GgswParameters, GlweParameters, SecretKeyDistr};
use primus_modulus::NativeModulus;
use primus_tfhe_glwe_fourier::{
    BooleanDecryptor, BooleanEncryptor, BooleanEvaluator, BooleanGate, PbsOrder, TfheContext,
    TfheParameters,
};

const POLY_LENGTH: usize = 256;

fn parameters() -> TfheParameters<u32> {
    parameters_with_order(PbsOrder::BootstrapKeyswitch)
}

fn parameters_with_order(pbs_order: PbsOrder) -> TfheParameters<u32> {
    let lwe = LweParameters::new(4, 4, NativeModulus::new(), SecretKeyDistr::Binary, 0.7);
    let glwe = GlweParameters::new(
        1,
        POLY_LENGTH,
        4,
        NativeModulus::new(),
        SecretKeyDistr::Binary,
        0.7,
    );
    let bootstrapping = GgswParameters::with_glwe_params(&glwe, 8, Some(3));
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
fn evaluates_boolean_gates_with_keyswitch_then_bootstrap() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context =
        TfheContext::try_new(parameters_with_order(PbsOrder::KeyswitchBootstrap), table).unwrap();
    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = BooleanEncryptor::new(context.parameters(), &client_key).unwrap();
    let decryptor = BooleanDecryptor::new(context.parameters(), &client_key).unwrap();
    let pbs_evaluator = context.evaluator(&server_key).unwrap();
    let mut evaluator = BooleanEvaluator::try_new(context.parameters(), pbs_evaluator).unwrap();
    let dimension = context.parameters().ciphertext_lwe_dimension();

    for lhs in [false, true] {
        for rhs in [false, true] {
            let lhs_ciphertext = encryptor.encrypt(lhs, &mut rng).unwrap();
            let rhs_ciphertext = encryptor.encrypt(rhs, &mut rng).unwrap();
            assert_eq!(lhs_ciphertext.as_raw().dimension(), dimension);
            for (gate, expected) in [
                (BooleanGate::And, lhs & rhs),
                (BooleanGate::Nand, !(lhs & rhs)),
                (BooleanGate::Or, lhs | rhs),
                (BooleanGate::Nor, !(lhs | rhs)),
                (BooleanGate::Xor, lhs ^ rhs),
                (BooleanGate::Xnor, !(lhs ^ rhs)),
            ] {
                let output = evaluator.evaluate_binary(gate, &lhs_ciphertext, &rhs_ciphertext);
                assert_eq!(decryptor.decrypt(&output).unwrap(), expected, "{gate:?}");
            }
        }
    }
}

#[test]
fn evaluates_boolean_helpers_and_reused_output() {
    let table = RustFftTable::new(POLY_LENGTH.trailing_zeros()).unwrap();
    let context = TfheContext::try_new(parameters(), table).unwrap();
    let mut rng = rand::rng();
    let (client_key, server_key) = context.generate_keys(&mut rng).unwrap();
    let encryptor = BooleanEncryptor::new(context.parameters(), &client_key).unwrap();
    let decryptor = BooleanDecryptor::new(context.parameters(), &client_key).unwrap();
    let pbs_evaluator = context.evaluator(&server_key).unwrap();
    let mut evaluator = BooleanEvaluator::try_new(context.parameters(), pbs_evaluator).unwrap();

    for value in [false, true] {
        let input = encryptor.encrypt(value, &mut rng).unwrap();
        let output = evaluator.not(&input);
        assert_eq!(decryptor.decrypt(&output).unwrap(), !value);
    }

    for condition in [false, true] {
        for then_value in [false, true] {
            for else_value in [false, true] {
                let condition_ciphertext = encryptor.encrypt(condition, &mut rng).unwrap();
                let then_ciphertext = encryptor.encrypt(then_value, &mut rng).unwrap();
                let else_ciphertext = encryptor.encrypt(else_value, &mut rng).unwrap();
                let output =
                    evaluator.mux(&condition_ciphertext, &then_ciphertext, &else_ciphertext);
                assert_eq!(
                    decryptor.decrypt(&output).unwrap(),
                    if condition { then_value } else { else_value }
                );
            }
        }
    }

    let true_ciphertext = encryptor.encrypt(true, &mut rng).unwrap();
    let mut current = encryptor.encrypt(false, &mut rng).unwrap();
    let mut next = current.clone();
    for _ in 0..16 {
        evaluator.evaluate_binary_to(BooleanGate::Nand, &current, &true_ciphertext, &mut next);
        core::mem::swap(&mut current, &mut next);
    }
    assert!(!decryptor.decrypt(&current).unwrap());
}
